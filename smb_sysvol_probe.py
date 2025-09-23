[2025-09-23 13:25:15] # cat smb_sysvol_probe2.py

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#Robust SMB SYSVOL probe w/o listShares()
#
#options:
#  -h, --help            show this help message and exit
#  -H HOST, --host HOST  DC FQDN (remoteName), e.g. dc1.smoke.local
#  --ip IP               DC IP (remoteHost). If omitted, uses FQDN for both.
#  -d DOMAIN, --domain DOMAIN
#  -u USERNAME, --username USERNAME
#  -p PASSWORD, --password PASSWORD
#  --show-gpt

import argparse, io, sys
from impacket.smbconnection import SMBConnection, SessionError

def try_list(smb, share, path):
    try:
        entries = smb.listPath(share, path)
        return True, entries, None
    except Exception as e:
        return False, None, e

def main():
    ap = argparse.ArgumentParser(description="Robust SMB SYSVOL probe w/o listShares()")
    ap.add_argument("-H","--host", required=True, help="DC FQDN (remoteName), e.g. dc1.smoke.local")
    ap.add_argument("--ip", help="DC IP (remoteHost). If omitted, uses FQDN for both.")
    ap.add_argument("-d","--domain", required=True)
    ap.add_argument("-u","--username", required=True)
    ap.add_argument("-p","--password", required=True)
    ap.add_argument("--show-gpt", action="store_true")
    args = ap.parse_args()

    remoteName = args.host
    remoteHost = args.ip or args.host

    print(f"[+] SMB auth to {remoteName} ({remoteHost}) as {args.domain}\\{args.username}")
    smb = SMBConnection(remoteName, remoteHost, sess_port=445)
    smb.login(user=args.username, password=args.password, domain=args.domain)

    # Try both common casings and both policy roots (some environments expect lowercase domain in path)
    shares = ["SYSVOL", "SysVol"]
    policy_roots = [f"\\{args.domain}\\Policies\\*", f"\\{args.domain.upper()}\\Policies\\*", f"\\{args.domain.lower()}\\Policies\\*"]

    chosen = None
    last_err = None
    for sh in shares:
        # quick sanity: the share root
        ok_root, _, err_root = try_list(smb, sh, "\\*")
        if not ok_root:
            last_err = err_root
            continue
        # try each policy root variant
        for pr in policy_roots:
            ok, entries, err = try_list(smb, sh, pr)
            if ok:
                chosen = (sh, pr, entries); break
            last_err = err
        if chosen:
            break

    if not chosen:
        smb.logoff()
        print("[-] Could not list Policies under SYSVOL.")
        if isinstance(last_err, SessionError):
            print(f"    Last SMB error: {last_err}")
        else:
            print(f"    Last error: {last_err}")
        print("    Tips: use --ip <DC_IP>; verify auth; try another DC; confirm SYSVOL share exists.")
        sys.exit(1)

    share, rel, entries = chosen
    print(f"[+] Using {share}{rel}")
    guids = [e.get_longname() for e in entries if e.is_directory() and e.get_longname().startswith("{")]
    if not guids:
        print("[.] No GPO GUID folders found under Policies (unexpected on a DC).")

    for g in guids:
        print(f"    - {g}")

    if args.show_gpt and guids:
        rel_inf = r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        print("[+] Reading first ~30 lines of GptTmpl.inf (if present):")
        for g in guids:
            remote = f"{rel[:-1]}{g}\\{rel_inf}"  # rel ends with '*'
            try:
                buf = io.BytesIO()
                smb.getFile(share, remote, buf.write)
                data = buf.getvalue()
                text = (data.decode("utf-16le", errors="ignore")
                        if data[:2] == b'\xff\xfe' else data.decode("utf-8", errors="ignore"))
                print(f"\n--- {share}{remote} ---")
                for line in text.splitlines()[:30]:
                    print(line)
            except Exception as e:
                print(f"[.] {g}: no GptTmpl.inf ({e})")

    smb.logoff()
    print("[+] Done.")

if __name__ == "__main__":
    main()
