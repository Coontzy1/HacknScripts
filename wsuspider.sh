#!/bin/bash

# =============================
# WSUS Registry Policy Extractor via manspider
# Author : Austin Coontz
# Date   : July 2025
# =============================

# Colors
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[1;31m'
NC='\033[0m'

print_banner() {
    echo -e "${RED}"
    cat << "EOF"
                              (_)   | |             | |    
 __      _____ _   _ ___ _ __  _  __| | ___ _ __ ___| |__  
 \ \ /\ / / __| | | / __| '_ \| |/ _` |/ _ \ '__/ __| '_ \ 
  \ V  V /\__ \ |_| \__ \ |_) | | (_| |  __/ |_ \__ \ | | |
   \_/\_/ |___/\__,_|___/ .__/|_|\__,_|\___|_(_)|___/_| |_|
                        | |                                
                        |_|                                

EOF
    echo -e "Austin Coontz${NC}"
}

# Default banner behavior
hacking_the_matrix=1
PARSE_ONLY=0

check_regpol() {
    if ! command -v regpol >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] regpol not found. Would you like to install it? (y/N)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[*] Installing regpol...${NC}"
            proxychains -q pipx install regpol
        else
            echo -e "${RED}[-] regpol is required. Install with: pipx install regpol${NC}"
            exit 1
        fi
    fi
}

check_regpol

# Usage/help
usage() {
    echo -e "${YELLOW}Usage:${NC} $0 -dc-ip <IP> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> --no-banner"
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -dc-ip           or --dc-ip <IP>             Domain Controller IP"
    echo -e "  -d               or --domain|--Domain         Domain name"
    echo -e "  -u               or --user|--username         Username"
    echo -e "  -p               or --password|--Password     Password"
    echo -e "  -n               or --no-banner|-no-banner    Don't show the banner"
    echo -e "  -e          or --parse|--parse-only      Only parse existing loot, skip manspider"
    echo -e "  -h               or --help                    Show this help menu"
    exit 1
}

# Parse args (handle both upper and lower case explicitly)
while [[ $# -gt 0 ]]; do
    case "$1" in
        -dc-ip|--dc-ip|-DC-IP|--DC-IP)
            DCIP="$2"; shift 2;;
        -d|--domain|-D|--Domain|--DOMAIN)
            DOMAIN="$2"; shift 2;;
        -u|--user|--username|-U|--User|--Username|--USERNAME)
            USERNAME="$2"; shift 2;;
        -p|--password|-P|--Password|--PASSWORD)
            PASSWORD="$2"; shift 2;;
        -n|--no-banner|-no-banner|-N|--No-Banner|--NO-BANNER)
            hacking_the_matrix=2; shift;;
        -e|-E|--parse|--parse-only|--Parse|--Parse-Only|--PARSE|--PARSE-ONLY)
            PARSE_ONLY=1; shift;;
        -h|--help|-H|--Help|--HELP)
            usage;;
        *)
            echo -e "${RED}[-] Unknown option:${NC} $1"
            usage;;
    esac
done

if [[ "$PARSE_ONLY" -eq 0 ]]; then
    if [[ -z "$DCIP" || -z "$DOMAIN" || -z "$USERNAME" || -z "$PASSWORD" ]]; then
        usage
    fi
fi

# Show banner
for ((i=1; i<=hacking_the_matrix; i++)); do
    print_banner
done

# Setup
LOOT_DIR="/root/.manspider/loot"
OUTDIR="parsed_reg_files"
SUMMARY="wsus_summary.txt"

mkdir -p "$OUTDIR"
echo "WSUS Summary - Generated on $(date)" >> "$SUMMARY"

# =============================
# Step 0: Run manspider
# =============================
# Modify manspider step
if [[ "$PARSE_ONLY" -eq 0 ]]; then
    echo -e "${BLUE}[*] Step 0:${NC} Running manspider against ${CYAN}$DCIP${NC}..."
    manspider "$DCIP" -d "$DOMAIN" -u "$USERNAME" -p "$PASSWORD" --sharenames SYSVOL -f Registry -e pol > /dev/null 2>&1
else
    echo -e "${YELLOW}[!] Parse-only mode enabled. Skipping manspider...${NC}"
fi

# =============================
# Step 1: Decode *Machine_Registry.pol files
# =============================
echo -e "${BLUE}[*] Step 1:${NC} Decoding Machine registry policy files..."
find "$LOOT_DIR" -type f -iname '*_Machine_Registry.pol' | while read -r polfile; do
    outfile="$OUTDIR/$(basename "$polfile" .pol).txt"
    /root/.local/bin/regpol "$polfile" > "$outfile"
    echo -e "${GREEN}[+] Decoded:${NC} $polfile -> $outfile"
done

cd "$OUTDIR" || exit 1

# =============================
# Step 2: Parse for WSUS values
# =============================
echo -e "${BLUE}[*] Step 2:${NC} Parsing registry text files for WSUS policy values..."

# REG_SZ keys
string_keys=(WUServer WUStatusServer TargetGroup)

# REG_DWORD keys
dword_keys=(
  UseWUServer AUOptions ScheduledInstallDay ScheduledInstallTime RescheduleWaitTime
  NoAutoUpdate DetectionFrequencyEnabled DetectionFrequency RebootWarningTimeout
  RebootRelaunchTimeout RebootRelaunchTimeoutEnabled IncludeRecommendedUpdates AutoInstallMinorUpdates
)

for file in *.txt; do
    domain=$(echo "$file" | cut -d'_' -f3)
    gpoid=$(echo "$file" | sed -n 's/.*Policies_\([A-F0-9]\{32\}\)_Machine.*/\1/pI')
    label="$domain-$gpoid"

    # REG_SZ
    for key in "${string_keys[@]}"; do
        raw=$(grep -iaA4 "value: $key" "$file" | grep -ai 'data:' | head -1 | sed -E "s/^.*b'(.*)'/\1/")
        if [[ -n "$raw" ]]; then
            val=$(python3 -c "import sys, ast; print(ast.literal_eval(f\"b'{sys.stdin.read().strip()}'\").decode('utf-16le'))" <<< "$raw" 2>/dev/null)
            echo "$label - $key - $val" | tee -a "../$SUMMARY"
        fi
    done

    # REG_DWORD
    for key in "${dword_keys[@]}"; do
        raw=$(grep -iaA4 -P "value:\s*${key}\\b" "$file" | grep -aPo "data:\s+b'\K(.*)(?=')" | head -1)
        if [[ -n "$raw" ]]; then
            decoded=$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex(sys.stdin.read().replace('\\\\x','')), 'little'))" <<< "$raw" 2>/dev/null)
            echo "$label - $key - $decoded" | tee -a "../$SUMMARY"
        fi
    done
done

echo -e "${GREEN}[+] Complete.${NC} Parsed output saved to ${CYAN}$SUMMARY${NC}"
