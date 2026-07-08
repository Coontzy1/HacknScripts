#!/usr/bin/env python3
"""
parse_sysvol.py - Unified SYSVOL recon and BloodHound correlation.

Walks a cloned SYSVOL directory and identifies GPO configurations
(software installs, drive maps, logon/startup scripts). Optionally
correlates with BloodHound JSON to show which OUs, users, and computers
are affected. Flags UNC paths outside SYSVOL as ARP-spoofable targets.

Subcommands:
    gpo       List all GPOs with metadata and linked OUs/targets
    software  Find .aas software installation policies
    drives    Find Drives.xml drive mappings
    scripts   Find scripts.ini / psscripts.ini logon/startup scripts
    all       Run every parser and print a combined report

Usage:
    parse_sysvol.py gpo -s ./sysvol -b ./bloodhound/
    parse_sysvol.py software -s ./sysvol -b ./bloodhound/
    parse_sysvol.py drives -s ./sysvol -b ./bloodhound/
    parse_sysvol.py scripts -s ./sysvol -b ./bloodhound/ --follow
    parse_sysvol.py all -s ./sysvol -b ./bloodhound/
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# BloodHound correlation helpers
# ---------------------------------------------------------------------------

def load_json(path):
    with open(path) as f:
        return json.load(f)["data"]


def find_bh_files(bh_dir):
    """Find BloodHound JSON files, handling both flat and nested directory layouts."""
    bh_dir = Path(bh_dir)
    files = {}
    for kind in ["users", "computers", "groups", "gpos", "ous", "domains", "containers"]:
        matches = list(bh_dir.glob(f"*_{kind}.json"))
        if not matches:
            matches = list(bh_dir.rglob(f"*_{kind}.json"))
        files[kind] = matches
    return files


def build_sid_name_map(bh_files):
    """SID -> friendly name from BloodHound user/computer/group JSONs."""
    sid_map = {}
    for kind in ["users", "computers", "groups"]:
        for path in bh_files.get(kind, []):
            for obj in load_json(path):
                sid = obj.get("ObjectIdentifier", "")
                name = obj.get("Properties", {}).get("name", sid)
                sid_map[sid] = name
    return sid_map


def build_gpo_map(bh_files):
    """SYSVOL policy folder GUID -> {name, bh_id} from BloodHound GPO JSONs."""
    gpo_map = {}
    for path in bh_files.get("gpos", []):
        for gpo in load_json(path):
            gpcpath = gpo.get("Properties", {}).get("gpcpath", "")
            match = re.search(r"\{([A-Fa-f0-9\-]+)\}", gpcpath)
            if match:
                sysvol_guid = "{" + match.group(1).upper() + "}"
                gpo_map[sysvol_guid] = {
                    "name": gpo["Properties"].get("name", "Unknown"),
                    "bh_id": gpo["ObjectIdentifier"],
                }
    return gpo_map


def build_gpo_to_targets(bh_files, sid_map):
    """
    For each GPO's BloodHound ObjectIdentifier, find which OUs/domains/containers
    link to it, then collect child users and computers (recursively).
    """
    gpo_targets = defaultdict(lambda: {"users": set(), "computers": set(), "ous": []})

    linkable = []
    for kind in ["ous", "domains", "containers"]:
        for path in bh_files.get(kind, []):
            linkable.extend(load_json(path))

    container_map = {obj["ObjectIdentifier"]: obj for obj in linkable}

    def collect_children(container, users, computers, visited=None):
        if visited is None:
            visited = set()
        cid = container["ObjectIdentifier"]
        if cid in visited:
            return
        visited.add(cid)
        for child in container.get("ChildObjects", []):
            child_id = child["ObjectIdentifier"]
            child_type = child.get("ObjectType", "")
            name = sid_map.get(child_id, child_id)
            if child_type == "User":
                users.add(name)
            elif child_type == "Computer":
                computers.add(name)
            elif child_type in ("OU", "Container"):
                if child_id in container_map:
                    collect_children(container_map[child_id], users, computers, visited)

    for container in linkable:
        for link in container.get("Links", []):
            gpo_bh_id = link.get("GUID", "")
            if not gpo_bh_id:
                continue
            ou_name = container.get("Properties", {}).get("name", "?")
            enforced = link.get("IsEnforced", False)
            gpo_targets[gpo_bh_id]["ous"].append(
                f"{ou_name}{' [ENFORCED]' if enforced else ''}"
            )
            users, computers = set(), set()
            collect_children(container, users, computers)
            gpo_targets[gpo_bh_id]["users"].update(users)
            gpo_targets[gpo_bh_id]["computers"].update(computers)

    return gpo_targets


def load_bloodhound(bloodhound_dir, verbose=True):
    """Unified loader. Returns (gpo_map, gpo_targets, has_bh, sid_map) or empty structures."""
    if not bloodhound_dir:
        if verbose:
            print("[*] No BloodHound data provided, skipping correlation")
        return {}, {}, False, {}

    bh_dir = Path(bloodhound_dir).resolve()
    if not bh_dir.exists():
        print(f"[!] BloodHound path not found: {bh_dir}")
        sys.exit(1)

    if verbose:
        print(f"[*] Loading BloodHound JSON data from {bh_dir}")
    bh_files = find_bh_files(bh_dir)
    found = {k: len(v) for k, v in bh_files.items() if v}
    if not found:
        print(f"[!] No BloodHound JSON files found in {bh_dir}")
        return {}, {}, False, {}
    if verbose:
        print(f"    Found: {', '.join(f'{k}({v})' for k, v in found.items())}")

    sid_map = build_sid_name_map(bh_files)
    gpo_map = build_gpo_map(bh_files)
    gpo_targets = build_gpo_to_targets(bh_files, sid_map)
    return gpo_map, gpo_targets, True, sid_map


def print_gpo_context(guid, gpo_map, gpo_targets, indent="    "):
    """Print GPO name, linked OUs, and affected users/computers for a policy GUID."""
    gpo_info = gpo_map.get(guid)
    if not gpo_info:
        print(f"{indent}[!] Policy GUID not found in BloodHound (orphaned or new)")
        return
    bh_id = gpo_info["bh_id"]
    print(f"{indent}GPO Name: {gpo_info['name']}")
    targets = gpo_targets.get(bh_id)
    if not targets:
        print(f"{indent}[!] GPO is not linked to any OU/domain")
        return
    if targets["ous"]:
        print(f"{indent}Linked To:")
        for ou in sorted(targets["ous"]):
            print(f"{indent}  - {ou}")
    if targets["computers"]:
        print(f"{indent}Affected Computers:")
        for c in sorted(targets["computers"]):
            print(f"{indent}  - {c}")
    if targets["users"]:
        print(f"{indent}Affected Users:")
        for u in sorted(targets["users"]):
            print(f"{indent}  - {u}")
    if not targets["computers"] and not targets["users"]:
        print(f"{indent}[!] GPO linked but no child users/computers in target OUs")


def policy_guid_from_path(file_path):
    for part in str(file_path).split(os.sep):
        if part.startswith("{") and part.endswith("}"):
            return part.upper()
    return "Unknown"


# ---------------------------------------------------------------------------
# Text file helpers (reading .bat / .ps1 / gpo.ini / scripts.ini)
# ---------------------------------------------------------------------------

def read_text_file(path):
    """Read a text file, trying common Windows encodings (UTF-16 BOM first)."""
    for encoding in ("utf-16", "utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            with open(path, "r", encoding=encoding) as f:
                return f.read()
        except (UnicodeError, UnicodeDecodeError, OSError):
            continue
    return None


UNC_IN_TEXT = re.compile(r"\\\\([A-Za-z0-9_.$\-]+)\\([A-Za-z0-9_.$\-]+)(?:\\[^\s\"'<>|]*)?")


def find_unc_references_in_file(path):
    """Return a list of (host, share, full_match) UNC paths referenced inside a text file."""
    raw = read_text_file(path)
    if raw is None:
        return []
    refs = []
    for m in UNC_IN_TEXT.finditer(raw):
        refs.append({"host": m.group(1), "share": m.group(2), "match": m.group(0)})
    return refs


# ---------------------------------------------------------------------------
# GPO enumeration (gpo.ini metadata + setting detection)
# ---------------------------------------------------------------------------

def parse_gpo_ini(gpo_ini_path):
    """Parse gpo.ini for DisplayName and Version."""
    raw = read_text_file(gpo_ini_path)
    if raw is None:
        return {}
    info = {}
    for line in raw.splitlines():
        m = re.match(r"\s*(\w+)\s*=\s*(.+?)\s*$", line)
        if m:
            info[m.group(1).lower()] = m.group(2)
    return info


def enumerate_gpos(sysvol_root):
    """
    Walk SYSVOL Policies directories and return a list of dicts describing
    every GPO found, including the types of settings each one contains.
    """
    results = []
    for gpo_dir in sysvol_root.rglob("Policies/*"):
        name = gpo_dir.name
        if not (name.startswith("{") and name.endswith("}")):
            continue
        if not gpo_dir.is_dir():
            continue
        guid = name.upper()

        gpo_ini = None
        for candidate in gpo_dir.rglob("gpt.ini"):
            gpo_ini = candidate
            break
        if gpo_ini is None:
            gpo_ini = gpo_dir / "GPT.INI"

        ini_info = parse_gpo_ini(gpo_ini) if gpo_ini.exists() else {}

        has_software = any(gpo_dir.rglob("*.aas"))
        has_drives = any(gpo_dir.rglob("Drives/Drives.xml"))
        has_scripts = any(gpo_dir.rglob("Scripts/**/scripts.ini")) or \
                      any(gpo_dir.rglob("Scripts/**/psscripts.ini"))
        has_registry = any(gpo_dir.rglob("Registry.pol"))
        has_preferences = any(gpo_dir.rglob("Preferences/**/*.xml"))

        setting_types = []
        if has_software:
            setting_types.append("Software Install")
        if has_drives:
            setting_types.append("Drive Maps")
        if has_scripts:
            setting_types.append("Scripts")
        if has_registry:
            setting_types.append("Registry")
        if has_preferences:
            setting_types.append("Preferences")

        results.append({
            "guid": guid,
            "path": gpo_dir,
            "display_name": ini_info.get("displayname", ""),
            "version": ini_info.get("version", ""),
            "setting_types": setting_types,
        })
    return results


# ---------------------------------------------------------------------------
# .aas (software installation) parsing
# ---------------------------------------------------------------------------

def parse_aas_file(file_path):
    """Extract product name, package name, launch path, and codes from a .aas file."""
    with open(file_path, "rb") as f:
        data = f.read()

    mtime = os.path.getmtime(file_path)
    info = {
        "file": str(file_path),
        "product_key": None,
        "package_code": None,
        "product_name": None,
        "package_name": None,
        "launch_path": None,
        "mtime": mtime,
        "mtime_str": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "policy_guid": policy_guid_from_path(file_path),
        "aas_guid": file_path.stem.upper(),
    }

    guid_pattern = rb'\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}'
    guids = list(re.finditer(guid_pattern, data))
    if guids:
        info["product_key"] = data[guids[0].start():guids[0].end()].decode("ascii")
    if len(guids) >= 2:
        info["package_code"] = data[guids[1].start():guids[1].end()].decode("ascii")

    unc_pattern = rb'\\\\[^\x00\x80\x40]{2,}\\[^\x00\x80\x40]+\\'
    unc_matches = list(re.finditer(unc_pattern, data))
    if unc_matches:
        info["launch_path"] = unc_matches[0].group().decode("ascii", errors="ignore")

    msi_matches = list(re.finditer(rb'[A-Za-z0-9_\-]+\.msi', data))
    if msi_matches:
        info["package_name"] = msi_matches[0].group().decode("ascii")

    # Product name: printable string right after the first GUID
    if guids:
        pos = guids[0].end()
        while pos < len(data) and data[pos] in (0x00, 0x0a, 0x0d):
            pos += 1
        if pos < len(data):
            str_len = data[pos]
            pos += 1
            if pos < len(data) and data[pos] == 0x00:
                pos += 1
            if str_len and pos + str_len <= len(data):
                candidate = data[pos:pos + str_len]
                try:
                    name = candidate.decode("ascii").strip("\x00")
                    if name.isprintable() and len(name) > 1:
                        info["product_name"] = name
                except (UnicodeDecodeError, ValueError):
                    pass
    return info


# ---------------------------------------------------------------------------
# Drives.xml parsing
# ---------------------------------------------------------------------------

def parse_drives_xml(file_path):
    mappings = []
    try:
        tree = ET.parse(file_path)
    except ET.ParseError:
        return mappings
    root = tree.getroot()
    policy_guid = policy_guid_from_path(file_path)

    for drive in root.findall(".//Drive"):
        props = drive.find("Properties")
        if props is None:
            continue
        path = props.get("path", "")
        m = re.match(r"\\\\([^\\]+)\\(.+)", path)
        if not m:
            continue
        mappings.append({
            "hostname": m.group(1).upper(),
            "share": m.group(2),
            "unc_path": path,
            "drive_letter": props.get("letter", "") or drive.get("name", ""),
            "label": props.get("label", ""),
            "action": props.get("action", ""),
            "policy_guid": policy_guid,
            "changed": drive.get("changed", ""),
        })
    return mappings


# ---------------------------------------------------------------------------
# scripts.ini / psscripts.ini parsing
# ---------------------------------------------------------------------------

SCRIPT_SECTION_CONTEXT = {
    "Startup":  "SYSTEM",
    "Shutdown": "SYSTEM",
    "Logon":    "User",
    "Logoff":   "User",
}


def parse_scripts_ini(file_path):
    raw = read_text_file(file_path)
    if raw is None:
        return []
    is_powershell = file_path.name.lower() == "psscripts.ini"
    grouped = defaultdict(lambda: defaultdict(dict))
    current_section = None

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            current_section = m.group(1)
            continue
        if current_section is None:
            continue
        m = re.match(r"^(\d+)(CmdLine|Parameters)\s*=\s*(.*)$", line, re.IGNORECASE)
        if not m:
            continue
        grouped[current_section][int(m.group(1))][m.group(2).lower()] = m.group(3).strip()

    entries = []
    for section, index_map in grouped.items():
        for idx in sorted(index_map):
            fields = index_map[idx]
            cmdline = fields.get("cmdline", "")
            parameters = fields.get("parameters", "")
            if not cmdline:
                continue
            unc_host = unc_share = None
            is_unc = False
            m = re.match(r"^\\\\([^\\]+)\\([^\\]+)", cmdline)
            if m:
                is_unc = True
                unc_host, unc_share = m.group(1), m.group(2)
            entries.append({
                "section": section,
                "index": idx,
                "cmdline": cmdline,
                "parameters": parameters,
                "is_unc": is_unc,
                "unc_host": unc_host,
                "unc_share": unc_share,
                "is_powershell": is_powershell,
                "file": str(file_path),
                "context": SCRIPT_SECTION_CONTEXT.get(section, "Unknown"),
                "policy_guid": policy_guid_from_path(file_path),
            })
    return entries


def resolve_local_script(ini_file, cmdline):
    """
    If CmdLine is a relative path, resolve it to the actual file inside the
    GPO's Scripts/<Section> directory so we can read its contents.
    """
    if cmdline.startswith("\\\\") or re.match(r"^[A-Za-z]:\\", cmdline):
        return None
    ini_path = Path(ini_file)
    candidate = ini_path.parent / cmdline
    if candidate.exists():
        return candidate
    # Some scripts.ini live one level up from the actual script file
    for parent in ini_path.parents:
        alt = parent / cmdline
        if alt.exists():
            return alt
        if parent.name.lower() == "scripts":
            break
    return None


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_gpo(args):
    sysvol_root = Path(args.sysvol).resolve()
    if not sysvol_root.exists():
        print(f"[!] SYSVOL path not found: {sysvol_root}")
        sys.exit(1)

    gpo_map, gpo_targets, has_bh, _ = load_bloodhound(args.bloodhound)

    gpos = enumerate_gpos(sysvol_root)
    if not gpos:
        print("[!] No GPOs found in SYSVOL (expected directories like Policies/{GUID}).")
        return

    print()
    print("=" * 70)
    title = "SYSVOL GPO Inventory"
    if has_bh:
        title += " + BloodHound Correlation"
    print(f"  {title}")
    print("=" * 70)

    for gpo in sorted(gpos, key=lambda g: g["guid"]):
        bh_name = gpo_map.get(gpo["guid"], {}).get("name", "")
        display = gpo["display_name"] or bh_name or "(unknown)"
        print(f"\n  {gpo['guid']}")
        print(f"    Display Name : {display}")
        if gpo["version"]:
            print(f"    Version      : {gpo['version']}")
        if gpo["setting_types"]:
            print(f"    Contains     : {', '.join(gpo['setting_types'])}")
        else:
            print(f"    Contains     : (no detected settings)")
        if has_bh:
            print_gpo_context(gpo["guid"], gpo_map, gpo_targets, indent="    ")

    print()
    print("=" * 70)
    print(f"  {len(gpos)} GPO(s) found in SYSVOL")
    if has_bh:
        linked = sum(1 for g in gpos if gpo_map.get(g["guid"]))
        print(f"  {linked} correlated with BloodHound")
    print("=" * 70)


def cmd_software(args):
    sysvol_root = Path(args.sysvol).resolve()
    if not sysvol_root.exists():
        print(f"[!] SYSVOL path not found: {sysvol_root}")
        sys.exit(1)

    gpo_map, gpo_targets, has_bh, _ = load_bloodhound(args.bloodhound)

    print(f"[*] Scanning for .aas files in {sysvol_root}")
    aas_files = list(sysvol_root.rglob("*.aas"))
    if not aas_files:
        print("[!] No .aas files found.")
        return

    apps = [parse_aas_file(f) for f in aas_files]
    apps = [a for a in apps if a["launch_path"] or a["package_name"]]
    if not apps:
        print("[!] No application deployments with UNC paths found.")
        return

    by_host = defaultdict(list)
    for app in apps:
        match = re.match(r"\\\\([^\\]+)\\", app["launch_path"] or "")
        host = match.group(1).upper() if match else "UNKNOWN"
        by_host[host].append(app)

    print()
    print("=" * 70)
    title = "SYSVOL Application Deployments (MSI)"
    if has_bh:
        title += " + BloodHound Correlation"
    print(f"  {title}")
    print("=" * 70)

    for host in sorted(by_host):
        print(f"\n  Target Host: {host}")
        print(f"  {'-' * 55}")
        for app in by_host[host]:
            pkg = app["package_name"] or "Unknown"
            path = app["launch_path"] or "Unknown"
            full_path = f"{path}{pkg}" if path.endswith("\\") else f"{path}\\{pkg}"
            print(f"    Package      : {pkg}")
            print(f"    Product      : {app['product_name'] or 'Unknown'}")
            print(f"    MSI Path     : {full_path}")
            print(f"    ProductCode  : {app['product_key'] or 'Unknown'}")
            print(f"    PackageCode  : {app['package_code'] or 'Unknown'}")
            print(f"    Last Modified: {app['mtime_str']}")
            print(f"    SYSVOL GUID  : {app['policy_guid']}")
            if has_bh:
                print_gpo_context(app["policy_guid"], gpo_map, gpo_targets, indent="    ")
            print()

    print("=" * 70)
    print(f"  {len(apps)} MSI deployment(s) across {len(by_host)} host(s)")
    print("=" * 70)
    print()
    print("  [*] NOTE: The malicious MSI you serve MUST match the advertised")
    print("      ProductCode and PackageCode, or Windows Installer will reject")
    print("      it with error 1612.")


def cmd_drives(args):
    sysvol_root = Path(args.sysvol).resolve()
    if not sysvol_root.exists():
        print(f"[!] SYSVOL path not found: {sysvol_root}")
        sys.exit(1)

    gpo_map, gpo_targets, has_bh, _ = load_bloodhound(args.bloodhound)

    print(f"[*] Parsing Drives.xml files in {sysvol_root}")
    drives_files = list(sysvol_root.rglob("Drives/Drives.xml"))
    if not drives_files:
        print("[!] No Drives.xml files found in SYSVOL.")
        return

    mappings = []
    for f in drives_files:
        mappings.extend(parse_drives_xml(f))
    if not mappings:
        print("[!] No drive mappings found.")
        return

    by_host = defaultdict(list)
    for m in mappings:
        by_host[m["hostname"]].append(m)

    print()
    print("=" * 70)
    title = "SYSVOL Drive Mappings"
    if has_bh:
        title += " + BloodHound Correlation"
    print(f"  {title}")
    print("=" * 70)

    for hostname in sorted(by_host):
        print(f"\n  Target Host: {hostname}")
        print(f"  {'-' * 55}")
        for e in by_host[hostname]:
            label = f' "{e["label"]}"' if e["label"] else ""
            print(f"    Drive {e['drive_letter']}: -> \\\\{hostname}\\{e['share']}{label}")
            print(f"    Action       : {e['action']}")
            print(f"    Changed      : {e['changed']}")
            print(f"    SYSVOL GUID  : {e['policy_guid']}")
            if has_bh:
                print_gpo_context(e["policy_guid"], gpo_map, gpo_targets, indent="    ")
            print()

    print("=" * 70)
    print(f"  {len(mappings)} drive mapping(s) across {len(by_host)} host(s)")
    print("=" * 70)


def cmd_scripts(args):
    sysvol_root = Path(args.sysvol).resolve()
    if not sysvol_root.exists():
        print(f"[!] SYSVOL path not found: {sysvol_root}")
        sys.exit(1)

    gpo_map, gpo_targets, has_bh, _ = load_bloodhound(args.bloodhound)

    print(f"[*] Scanning for scripts.ini / psscripts.ini in {sysvol_root}")
    ini_files = []
    for name in ("scripts.ini", "psscripts.ini"):
        ini_files.extend(sysvol_root.rglob(f"Scripts/**/{name}"))
        for candidate in sysvol_root.rglob("Scripts/**/*"):
            if candidate.is_file() and candidate.name.lower() == name and candidate not in ini_files:
                ini_files.append(candidate)
    ini_files = sorted(set(ini_files))
    if not ini_files:
        print("[!] No scripts.ini / psscripts.ini found in SYSVOL.")
        return

    all_entries = []
    for ini in ini_files:
        all_entries.extend(parse_scripts_ini(ini))
    if not all_entries:
        print("[!] No script entries parsed.")
        return

    by_guid = defaultdict(list)
    for e in all_entries:
        by_guid[e["policy_guid"]].append(e)

    print()
    print("=" * 70)
    title = "SYSVOL GPO Scripts (Startup/Shutdown/Logon/Logoff)"
    if has_bh:
        title += " + BloodHound Correlation"
    print(f"  {title}")
    print("=" * 70)

    unc_targets = defaultdict(set)

    order = {"Startup": 0, "Shutdown": 1, "Logon": 2, "Logoff": 3}
    for guid in sorted(by_guid):
        entries = sorted(by_guid[guid], key=lambda x: (order.get(x["section"], 99), x["index"]))
        print(f"\n  SYSVOL Policy GUID: {guid}")
        if has_bh:
            print_gpo_context(guid, gpo_map, gpo_targets, indent="  ")

        for e in entries:
            tag = "[PS]" if e["is_powershell"] else "[CMD]"
            print(f"  {'-' * 55}")
            print(f"    {tag} {e['section']} #{e['index']}  (runs as {e['context']})")
            print(f"      CmdLine    : {e['cmdline']}")
            if e["parameters"]:
                print(f"      Parameters : {e['parameters']}")

            if e["is_unc"]:
                print(f"      >>> UNC path! Target host: {e['unc_host']} "
                      f"(share: {e['unc_share']}) - ARP-spoofable")
                unc_targets[e["unc_host"].upper()].add(e["cmdline"])

            if args.follow:
                local_path = resolve_local_script(e["file"], e["cmdline"])
                if local_path and local_path.exists():
                    refs = find_unc_references_in_file(local_path)
                    if refs:
                        print(f"      >>> Nested UNC references in {local_path.name}:")
                        seen = set()
                        for ref in refs:
                            key = (ref["host"].upper(), ref["match"])
                            if key in seen:
                                continue
                            seen.add(key)
                            print(f"            {ref['match']}")
                            unc_targets[ref["host"].upper()].add(ref["match"])

    print()
    print("=" * 70)
    total = len(all_entries)
    unc_count = sum(1 for e in all_entries if e["is_unc"])
    print(f"  {total} script entr{'y' if total == 1 else 'ies'} across {len(by_guid)} GPO(s)")
    print(f"    UNC-referenced CmdLines: {unc_count}")
    print("=" * 70)

    if unc_targets:
        print()
        print("  [*] ARP-spoof targets:")
        for host, paths in sorted(unc_targets.items()):
            print(f"      {host}")
            for p in sorted(paths):
                print(f"        - {p}")


def cmd_all(args):
    cmd_gpo(args)
    print()
    cmd_software(args)
    print()
    cmd_drives(args)
    print()
    cmd_scripts(args)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="parse_sysvol.py",
        description="Unified SYSVOL recon + BloodHound correlation tool.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p, follow=False):
        p.add_argument("-s", "--sysvol", required=True,
                       help="Path to the cloned SYSVOL directory")
        p.add_argument("-b", "--bloodhound", default=None,
                       help="Path to BloodHound JSON directory (optional)")
        if follow:
            p.add_argument("--follow", action="store_true",
                           help="Follow relative CmdLine references into SYSVOL and "
                                "look for nested UNC paths inside .bat/.ps1/.cmd files")

    p_gpo = sub.add_parser("gpo", help="List all GPOs with metadata and linked OUs/targets")
    add_common(p_gpo)
    p_gpo.set_defaults(func=cmd_gpo)

    p_sw = sub.add_parser("software", help="Find .aas software installation policies")
    add_common(p_sw)
    p_sw.set_defaults(func=cmd_software)

    p_dr = sub.add_parser("drives", help="Find Drives.xml drive mappings")
    add_common(p_dr)
    p_dr.set_defaults(func=cmd_drives)

    p_sc = sub.add_parser("scripts", help="Find scripts.ini / psscripts.ini entries")
    add_common(p_sc, follow=True)
    p_sc.set_defaults(func=cmd_scripts)

    p_all = sub.add_parser("all", help="Run every parser and print a combined report")
    add_common(p_all, follow=True)
    p_all.set_defaults(func=cmd_all)

    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
