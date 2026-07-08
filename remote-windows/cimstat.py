#!/usr/bin/env python3
"""
cimstat — read remote file metadata over WSMAN/CIM, no PowerShell.

Research context: this started as an unfinished OPSEC idea to see whether
payload output could be written somewhere and read back through WMI metadata.
Windows' built-in CIM_DataFile provider does not expose file contents, so that
did not turn into a useful stdout channel. What remains is a small standalone
probe for testing whether files/directories are present and reading their WMI
metadata over WinRM/CIM from Python.

Sends a WSMAN Get to CIM_DataFile (root/cimv2) on the target with
Name="<path>" as the selector. The WinRM service hands it to wmiprvse.exe
which queries the file-system WMI provider directly. No PowerShell host
spawns, no scriptblock logging.

Note: CIM_DataFile exposes METADATA only (size, timestamps, attributes,
version-ish properties). It does NOT expose contents — Microsoft's WMI
providers do not implement CIM_DataFile.GetContent / ReadFile, despite
the DMTF schema defining abstract methods for it.

Usage:
    cimstat.py -u USER -p PASS [-d DOMAIN] -f 'C:\\path\\to\\file' HOST
"""
import argparse
import socket
import sys
import time
import xml.etree.ElementTree as ET

from pypsrp.wsman import WSMan, SelectorSet

CIM_DATAFILE_URI = (
    'http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/CIM_DataFile'
)

WIN32_DIRECTORY_URI = (
    'http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Directory'
)

def log(verbose: bool, msg: str):
    if verbose:
        print(f'[{time.strftime("%H:%M:%S")}] {msg}', file=sys.stderr)


def can_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def pick_transport(host: str, explicit_port, force_https, verbose: bool):
    if explicit_port is not None:
        use_ssl = force_https if force_https is not None else (explicit_port == 5986)
        log(verbose, f'[*] transport: explicit port {explicit_port}, ssl={use_ssl}')
        return use_ssl, explicit_port
    if force_https is True:
        log(verbose, '[*] transport: --https forced, using 5986')
        return True, 5986
    if force_https is False:
        log(verbose, '[*] transport: --http forced, using 5985')
        return False, 5985
    log(verbose, '[*] transport auto-detect: probing 5986 (HTTPS) ...')
    if can_connect(host, 5986):
        log(verbose, '[*] transport: 5986 open, using HTTPS')
        return True, 5986
    log(verbose, '[*] transport: 5986 closed, probing 5985 (HTTP) ...')
    if can_connect(host, 5985):
        log(verbose, '[*] transport: 5985 open, using HTTP')
        return False, 5985
    sys.exit(f'[!] neither 5985 nor 5986 reachable on {host}')


def extract_properties(elem: ET.Element) -> dict:
    """Pull leaf properties from a WMI/CIM response element into a dict."""
    candidates = [elem]
    candidates.extend(elem.iter())
    best, best_count = elem, 0
    for c in candidates:
        n = sum(1 for child in c if len(child) == 0 or child.text is not None)
        if n > best_count:
            best, best_count = c, n
    props = {}
    for child in best:
        tag = child.tag.split('}', 1)[-1]
        if tag in ('Header', 'Body', 'EndpointReference', 'ReferenceParameters'):
            continue
        nil = any(k.endswith('}nil') and v.lower() == 'true'
                  for k, v in child.attrib.items())
        if nil:
            props[tag] = None
        elif len(child) == 0:
            props[tag] = (child.text or '').strip()
        else:
            props[tag] = [((sub.text or '').strip()) for sub in child]
    return props


def parse_hashes(s: str):
    """Accept LM:NT or :NT. Empty LM is the standard PtH-only form."""
    if ':' not in s:
        sys.exit('[!] --hashes must be LM:NT or :NT')
    lm, nt = s.split(':', 1)
    return lm, nt


def winrm_credential(args):
    """Return a password or pyspnego LM:NT hash-pair string."""
    if getattr(args, 'hashes', None):
        lm, nt = parse_hashes(args.hashes)
        if not lm:
            lm = 'aad3b435b51404eeaad3b435b51404ee'
        return f'{lm}:{nt}'
    return args.password


def require_creds(args):
    if not args.kerberos and not args.password and not args.hashes:
        sys.exit('[!] one of -p/--password, --hashes, or -k/--kerberos is required')


def build_principal(args):
    if args.kerberos and args.domain:
        return f'{args.user}@{args.domain.upper()}'
    return f'{args.domain}\\{args.user}' if args.domain else args.user


def add_kerberos_args(parser):
    parser.add_argument('-k', '--kerberos', action='store_true',
                        help='Use Kerberos authentication instead of NTLM. '
                             'Supports password or ccache via KRB5CCNAME.')


def normalize_path(path: str) -> str:
    """Normalize shell-friendly path input for WMI's backslash path selector.
    The selector match is case-insensitive in practice, so preserve case."""
    p = path.replace('/', '\\')
    # Strip surrounding quotes if user shell-escaped
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]
    return p


def cim_get(wsman: WSMan, resource_uri: str, path: str) -> ET.Element:
    sel = SelectorSet()
    sel.add_option('Name', path)
    return wsman.get(resource_uri=resource_uri, selector_set=sel)


CIM_DATETIME_KEYS = {
    'CreationDate', 'LastAccessed', 'LastModified', 'InstallDate'
}


def fmt_cim_datetime(s: str) -> str:
    """CIM_DATETIME is yyyymmddHHMMSS.mmmmmm+UUU. Return ISO-ish."""
    if not s or len(s) < 21:
        return s
    try:
        date = f'{s[0:4]}-{s[4:6]}-{s[6:8]}'
        tm = f'{s[8:10]}:{s[10:12]}:{s[12:14]}.{s[15:21]}'
        tz = s[21:]  # +UUU minutes offset, or '+000'
        return f'{date}T{tm} {tz}'
    except Exception:
        return s


# Properties worth surfacing first, in order. Anything else gets dumped after.
PRIMARY_ORDER = [
    'Name', 'FileName', 'Extension', 'FileType', 'FileSize',
    'CreationDate', 'LastModified', 'LastAccessed', 'InstallDate',
    'Readable', 'Writeable', 'Executable', 'Hidden', 'System',
    'Archive', 'Compressed', 'Encrypted', 'EightDotThreeFileName',
    'Drive', 'Path', 'Manufacturer', 'Version',
    'Status', 'AccessMask', 'CSName', 'CSCreationClassName',
    'CreationClassName', 'FSName', 'FSCreationClassName',
]


def print_properties(props: dict, raw: bool):
    if raw:
        # Stable, machine-parseable output
        for k in sorted(props):
            v = props[k]
            print(f'{k}={v}')
        return

    seen = set()
    width = max((len(k) for k in props), default=0)

    def emit(k, v):
        if k in CIM_DATETIME_KEYS and isinstance(v, str):
            v = fmt_cim_datetime(v)
        if isinstance(v, list):
            v = ', '.join(v) if v else ''
        if v is None:
            v = '(null)'
        print(f'{k.ljust(width)}  {v}')

    for k in PRIMARY_ORDER:
        if k in props:
            emit(k, props[k])
            seen.add(k)
    extras = [k for k in props if k not in seen]
    if extras:
        print('-' * 40)
        for k in sorted(extras):
            emit(k, props[k])


def main():
    ap = argparse.ArgumentParser(description='Read remote file metadata via CIM_DataFile over WSMAN (no PowerShell).')
    ap.add_argument('host', help='Target hostname/IP')
    ap.add_argument('-u', '--user', required=True, help='Username')
    ap.add_argument('-p', '--password', default='', help='Password')
    ap.add_argument('--hashes', default='',
                    help='LM:NT or :NT for pass-the-hash. Either -p or --hashes is required.')
    ap.add_argument('-d', '--domain', default='', help='Domain (omit for local accounts)')
    add_kerberos_args(ap)
    ap.add_argument('-f', '--file', required=True,
                    help=r"Target path, e.g. 'C:\Windows\System32\notepad.exe'")
    ap.add_argument('--directory', action='store_true',
                    help='Treat target as a directory (Win32_Directory instead of CIM_DataFile)')
    ap.add_argument('--port', type=int, help='Override WinRM port (default: auto-detect)')
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument('--https', dest='https', action='store_true', default=None, help='Force HTTPS (5986)')
    grp.add_argument('--http', dest='https', action='store_false', help='Force HTTP (5985)')
    ap.add_argument('-t', '--timeout', type=int, default=120, help='Operation timeout (sec)')
    ap.add_argument('--raw', action='store_true', help='key=value output, sorted, no formatting')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Verbose step-by-step logging')
    args = ap.parse_args()
    require_creds(args)

    path = normalize_path(args.file)
    resource_uri = WIN32_DIRECTORY_URI if args.directory else CIM_DATAFILE_URI

    log(args.verbose, f'[*] target: {args.host}')
    log(args.verbose, f'[*] resource: {resource_uri.rsplit("/", 1)[-1]}')
    log(args.verbose, f'[*] path selector: Name={path!r}')

    ssl, port = pick_transport(args.host, args.port, args.https, args.verbose)
    user = build_principal(args)

    log(args.verbose, f'[*] auth principal: {user!r}')
    log(args.verbose, f'[*] auth scheme: {"Kerberos" if args.kerberos else "NTLMv2"} (via pyspnego)')
    log(args.verbose, '[*] sending WSMAN Get → CIM endpoint (wmiprvse.exe, no PowerShell host)')

    wsman = WSMan(
        args.host, port=port, ssl=ssl,
        username=user, password=winrm_credential(args),
        auth='kerberos' if args.kerberos else 'ntlm',
        cert_validation=False,
        operation_timeout=args.timeout,
        read_timeout=args.timeout + 30,
    )

    t_start = time.time()
    try:
        with wsman:
            resp = cim_get(wsman, resource_uri, path)
    except Exception as e:
        msg = str(e)
        # Common: "HTTP status code '500'" with WSManFault 2150858843 = not found
        if ('not found' in msg.lower() or '2150858843' in msg
                or '2150858752' in msg or 'ItemNotFound' in msg):
            sys.exit(f'[!] no such file on target: {path}')
        sys.exit(f'[!] CIM Get error: {e}')
    t_end = time.time()

    log(args.verbose, f'[*] round-trip: {t_end - t_start:.2f}s')

    if resp is None:
        sys.exit('[!] empty response from target')

    props = extract_properties(resp)
    if not props:
        log(args.verbose, '[!] no properties parsed; dumping raw XML:')
        sys.stderr.write(ET.tostring(resp, encoding='unicode'))
        sys.exit(1)

    print_properties(props, args.raw)


if __name__ == '__main__':
    main()
