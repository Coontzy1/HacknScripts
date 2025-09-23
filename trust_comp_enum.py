#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trust_enum_min.py
Low-priv LDAP/LDAPS trust enumeration + age coloring + computer pwdLastSet auditing.

Adds:
  --trust-accounts           : list UF_INTERDOMAIN_TRUST_ACCOUNT users (e.g., OTHERDOMAIN$)
  --created-since N          : only show trusts created within N days (0 = all)
  --computer-created-since N : only show computers created within N days (0 = all)
Computers print both pwdLastSet and whenCreated (with ages). Color is forced on.
"""

import argparse
import datetime as dt
import xml.etree.ElementTree as ET
from ldap3 import Server, Connection, SUBTREE, NTLM, Tls, ALL

# -------------------- ANSI colors (forced) --------------------
ANSI = {"RED":"\x1b[31m","GREEN":"\x1b[32m","YELLOW":"\x1b[33m","RESET":"\x1b[0m"}
def maybe_color(s, color): return f"{ANSI[color]}{s}{ANSI['RESET']}"
def color_age(days, threshold):
    if days is None: return "(n/a)"
    return maybe_color(f"{days} days", "GREEN") if days < threshold else maybe_color(f"{days} days", "RED")

# -------------------- maps & helpers --------------------
DIR_MAP  = {0:"Disabled",1:"Inbound",2:"Outbound",3:"Bidirectional"}
TYPE_MAP = {1:"Downlevel",2:"Uplevel",3:"MIT Kerberos",4:"DCE"}
ATTR_FLAGS = {
    0x00000001:"NonTransitive", 0x00000002:"UplevelOnly", 0x00000004:"Quarantined",
    0x00000008:"ForestTransitive", 0x00000010:"CrossOrganization", 0x00000020:"WithinForest",
    0x00000040:"TreatAsExternal", 0x00000080:"UsesAESKeys", 0x00000100:"CrossOrgNoTGTDeleg",
    0x00000200:"PIMTrust",
}
ENC_FLAGS = {0x1:"DES_CRC",0x2:"DES_MD5",0x4:"RC4_HMAC",0x8:"AES128_HMAC",0x10:"AES256_HMAC"}

def dn_from_domain(domain): return "DC=" + ",DC=".join(domain.split("."))

def decode_flags(value, table):
    try: value = int(value or 0)
    except Exception: return []
    return [name for bit, name in table.items() if value & bit]

def parse_repl_metadata(xml_blob):
    if isinstance(xml_blob, (list, tuple)): xml_blob = xml_blob[0]
    if not xml_blob: return {}
    try: root = ET.fromstring(xml_blob)
    except ET.ParseError: return {}
    info = {}
    for attr in root.findall(".//attribute"):
        name = attr.findtext("name")
        when = attr.findtext("lastOriginatingChangeTime")
        if name in ("trustAuthIncoming", "trustAuthOutgoing"): info[name] = when
    return info

def utc_now(): return dt.datetime.now(dt.timezone.utc)

def to_days_ago(any_ts):
    if any_ts is None: return None
    if isinstance(any_ts, dt.datetime):
        d = any_ts if any_ts.tzinfo else any_ts.replace(tzinfo=dt.timezone.utc)
    elif isinstance(any_ts, str):
        s = any_ts.replace("Z","+00:00")
        try:
            d = dt.datetime.fromisoformat(s)
            if d.tzinfo is None: d = d.replace(tzinfo=dt.timezone.utc)
        except ValueError: return None
    else: return None
    return max(0, int((utc_now() - d.astimezone(dt.timezone.utc)).total_seconds() // 86400))

# FILETIME helpers (100ns since 1601)
FILETIME_EPOCH = dt.datetime(1601,1,1,tzinfo=dt.timezone.utc)
def filetime_to_dt(v):
    if v in (None,"",0): return None
    try:
        iv = int(v); low = iv & 0xffffffff; high = (iv >> 32) & 0xffffffff
        val = (high << 32) + (low & 0xffffffff)
        return FILETIME_EPOCH + dt.timedelta(microseconds=val/10)
    except Exception:
        if isinstance(v, dt.datetime): return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)
        return None
def filetime_days_ago(v):
    d = filetime_to_dt(v)
    if not d: return None
    return max(0, int((utc_now() - d.astimezone(dt.timezone.utc)).total_seconds() // 86400))

# -------------------- Inter-domain trust accounts --------------------
# UF_INTERDOMAIN_TRUST_ACCOUNT = 0x0800 (2048)
def enumerate_trust_accounts(conn, base_dn):
    filt = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2048))'
    attrs = ['sAMAccountName','userAccountControl','pwdLastSet','lastLogonTimestamp']
    ok = conn.search(base_dn, filt, SUBTREE, attributes=attrs, paged_size=1000)
    if not ok or not conn.entries: return []
    rows = []
    for e in conn.entries:
        g = lambda a: getattr(e, a).value if hasattr(e, a) else None
        rows.append({
            'name': g('sAMAccountName') or '(unknown)',
            'pwdLastSetDays': filetime_days_ago(g('pwdLastSet')),
            'lastLogonDays': filetime_days_ago(g('lastLogonTimestamp')),
            'uac': int(g('userAccountControl') or 0),
        })
    rows.sort(key=lambda r: (r['name'] or ''))
    return rows

# -------------------- LDAP bind --------------------
def bind_ldap(host, domain, username, password, use_ssl=False, starttls=False, timeout=10):
    tls = Tls() if use_ssl else None
    server = Server(host, use_ssl=use_ssl, tls=tls, get_info=ALL, connect_timeout=timeout)
    conn = Connection(server, user=f"{domain}\\{username}", password=password,
                      authentication=NTLM, auto_bind=True if not starttls else False)
    if starttls:
        conn.open(); conn.start_tls(); conn.bind()
    return conn

# -------------------- Trust enumeration --------------------
def enumerate_trusts(conn, domain, base=None):
    base = base or f"CN=System,{dn_from_domain(domain)}"
    attrs = ["name","trustPartner","flatName","securityIdentifier","trustDirection",
             "trustType","trustAttributes","msDS-SupportedEncryptionTypes","whenCreated",
             "whenChanged","msDS-ReplAttributeMetaData"]
    ok = conn.search(base, "(objectClass=trustedDomain)", SUBTREE, attributes=attrs)
    if not ok or not conn.entries: return []
    rows = []
    for e in conn.entries:
        g = lambda a: getattr(e, a).value if hasattr(e, a) else None
        meta = parse_repl_metadata(g("msDS_ReplAttributeMetaData") or g("msDS-ReplAttributeMetaData"))
        rows.append({
            "dn": e.entry_dn,
            "trustPartner": g("trustPartner"),
            "flatName": g("flatName"),
            "sid": g("securityIdentifier"),
            "direction": DIR_MAP.get(int(g("trustDirection") or 0), str(g("trustDirection"))),
            "type": TYPE_MAP.get(int(g("trustType") or 0), str(g("trustType"))),
            "attrs": decode_flags(g("trustAttributes"), ATTR_FLAGS),
            "encs": decode_flags(g("msDS-SupportedEncryptionTypes"), ENC_FLAGS),
            "whenCreated": g("whenCreated"),
            "whenChanged": g("whenChanged"),
            "incChanged": meta.get("trustAuthIncoming"),
            "outChanged": meta.get("trustAuthOutgoing"),
        })
    return rows

# -------------------- Computers pwdLastSet + whenCreated --------------------
def enumerate_computers(conn, base_dn, threshold_days=30, created_since=0, limit=None):
    # Filter out disabled accounts (bit 2)
    filt = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    attrs = ['name','dNSHostName','pwdLastSet','whenCreated','userAccountControl','operatingSystem']
    ok = conn.search(base_dn, filt, SUBTREE, attributes=attrs, paged_size=1000)
    if not ok: return []
    rows = []
    for e in conn.entries:
        g = lambda a: getattr(e, a).value if hasattr(e, a) else None
        name = g('name'); dns = g('dNSHostName') or name
        pls = g('pwdLastSet'); pwd_dt = filetime_to_dt(pls); pwd_days = filetime_days_ago(pls)
        created = g('whenCreated'); created_days = to_days_ago(created)
        # Optional filter: only recently CREATED computer accounts
        if created_since and (created_days is None or created_days > created_since):
            continue
        rows.append({
            'name': name,
            'dns': dns,
            'pwdLastSet': pwd_dt.isoformat() if pwd_dt else '(n/a)',
            'pwdAgeDays': pwd_days,
            'stale': (pwd_days is not None and pwd_days >= threshold_days),
            'whenCreated': str(created) if created is not None else '(n/a)',
            'createdDays': created_days
        })
        if limit and len(rows) >= limit: break
    # Sort: newest creations first, then by oldest pwdLastSet
    rows.sort(key=lambda r: (999999 if r['createdDays'] is None else r['createdDays'],
                             -1 if r['pwdAgeDays'] is None else -r['pwdAgeDays']))
    return rows

# -------------------- CLI --------------------
def main():
    ap = argparse.ArgumentParser(description="Enumerate AD trusts and computer pwdLastSet via LDAP/LDAPS.")
    ap.add_argument("-H","--host", required=True, help="DC host (FQDN recommended)")
    ap.add_argument("-d","--domain", required=True, help="AD domain (e.g., SMOKE.LOCAL)")
    ap.add_argument("-u","--username", required=True)
    ap.add_argument("-p","--password", required=True)
    ap.add_argument("--base", default=None, help="Search base for trusts (defaults to CN=System,DC=...)")
    ap.add_argument("--ldaps", action="store_true", help="Use LDAPS (636)")
    ap.add_argument("--starttls", action="store_true", help="StartTLS on 389")
    ap.add_argument("--threshold-days", type=int, default=30, help="Color threshold for age fields (default 30)")
    ap.add_argument("--created-since", type=int, default=0, help="Only show trusts created within N days (0 = all)")
    ap.add_argument("--computers", action="store_true", help="Enumerate computers and flag pwdLastSet age")
    ap.add_argument("--computer-created-since", type=int, default=0,
                    help="Only show computers created within N days (0 = all)")
    ap.add_argument("--computer-limit", type=int, default=0, help="Limit printed computer rows (0 = all)")
    ap.add_argument("--trust-accounts", dest="trust_accounts", action="store_true",
                    help="Enumerate inter-domain trust accounts (UF_INTERDOMAIN_TRUST_ACCOUNT)")
    args = ap.parse_args()

    now = utc_now()
    domain_dn = dn_from_domain(args.domain)
    conn = bind_ldap(args.host, args.domain, args.username, args.password,
                     use_ssl=args.ldaps, starttls=args.starttls)

    print(f"Now (UTC): {now.isoformat()}")

    # ---- Trusts ----
    trusts = enumerate_trusts(conn, args.domain, base=args.base)
    if not trusts:
        print("[!] No trustedDomain objects found (or search failed).")
    for r in trusts:
        created_days = to_days_ago(r["whenCreated"])
        changed_days = to_days_ago(r["whenChanged"])
        inc_days = to_days_ago(r["incChanged"])
        out_days = to_days_ago(r["outChanged"])
        if args.created_since and (created_days is None or created_days > args.created_since):
            continue
        print("="*80)
        print(f"DN: {r['dn']}")
        print(f"Partner: {r['trustPartner']}   Flat: {r['flatName']}   SID: {r['sid']}")
        print(f"Direction: {r['direction']}   Type: {r['type']}")
        print(f"Attributes: {', '.join(r['attrs']) or '(none)'}")
        print(f"SupportedEnctypes: {', '.join(r['encs']) or '(unset)'}")
        print(f"whenCreated: {r['whenCreated']}   age: {color_age(created_days, args.threshold_days)}")
        print(f"whenChanged: {r['whenChanged']}   age: {color_age(changed_days, args.threshold_days)}")
        print(f"Last trustAuthIncoming change: {r['incChanged'] or '(n/a)'}   age: {color_age(inc_days, args.threshold_days)}")
        print(f"Last trustAuthOutgoing change: {r['outChanged'] or '(n/a)'}   age: {color_age(out_days, args.threshold_days)}")
        if created_days is not None and created_days <= args.threshold_days:
            print(maybe_color(f"[!] Newly created trust (created {created_days} days ago ≤ threshold {args.threshold_days})", "YELLOW"))
        if changed_days is not None and changed_days <= args.threshold_days:
            print(maybe_color(f"[!] Trust object recently changed ({changed_days} days ago ≤ threshold {args.threshold_days})", "YELLOW"))
        if inc_days is not None and inc_days <= args.threshold_days:
            print(maybe_color(f"[!] trustAuthIncoming rotated/updated {inc_days} days ago (≤ threshold)", "YELLOW"))
        if out_days is not None and out_days <= args.threshold_days:
            print(maybe_color(f"[!] trustAuthOutgoing rotated/updated {out_days} days ago (≤ threshold)", "YELLOW"))

    # ---- Computers ----
    if args.computers:
        rows = enumerate_computers(conn, domain_dn, threshold_days=args.threshold_days,
                                   created_since=args.computer_created_since, limit=args.computer_limit)
        print("="*80)
        filt_note = f" (created ≤ {args.computer_created_since} days)" if args.computer_created_since else ""
        print(f"Computer Accounts pwdLastSet (threshold {args.threshold_days} days){filt_note}")
        shown = 0
        for r in rows:
            age_pwd = "(n/a)" if r['pwdAgeDays'] is None else maybe_color(f"{r['pwdAgeDays']} days", "RED" if r['stale'] else "GREEN")
            age_created = r['createdDays']
            created_str = "(n/a)" if age_created is None else f"{age_created} days"
            print(f"- {r['name']:25s}  {r['dns']:<40s}  pwdLastSet: {r['pwdLastSet']:<30s}  age: {age_pwd}  "
                  f"created: {r['whenCreated']}  created_age: {created_str}")
            if age_created is not None and age_created <= args.threshold_days:
                print("  " + maybe_color(f"[!] Newly created computer account ({age_created} days ≤ threshold {args.threshold_days})", "YELLOW"))
            shown += 1
            if args.computer_limit and shown >= args.computer_limit:
                break

    # ---- Trust accounts ----
    if args.trust_accounts:
        print("="*80)
        print("Inter-domain trust accounts (UF_INTERDOMAIN_TRUST_ACCOUNT):")
        trows = enumerate_trust_accounts(conn, domain_dn)
        if not trows:
            print("- (none found)")
        else:
            for r in trows:
                pls = "(n/a)" if r['pwdLastSetDays'] is None else f"{r['pwdLastSetDays']} days"
                llt = "(n/a)" if r['lastLogonDays'] is None else f"{r['lastLogonDays']} days"
                print(f"- {r['name']:20s}  pwdLastSet: {pls:>10s}  lastLogon: {llt:>10s}  UAC=0x{r['uac']:08X}")

    conn.unbind()
    print("="*80)

if __name__ == "__main__":
    main()
