#!/bin/bash

# =============================
# WSUS Extractor via manspider
# =============================

# Colors
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[1;31m'
NC='\033[0m'

# Input args
DCIP="$1"
DOMAIN="$2"
USERNAME="$3"
PASSWORD="$4"

if [[ -z "$DCIP" || -z "$DOMAIN" || -z "$USERNAME" || -z "$PASSWORD" ]]; then
    echo -e "${YELLOW}[*] Usage:${NC} $0 <DC-IP> <DOMAIN> <USERNAME> <PASSWORD>"
    exit 1
fi

LOOT_DIR="/root/.manspider/loot"

# =============================
# Step 0: Run manspider
# =============================
echo -e "${BLUE}[*] Step 0:${NC} Running manspider against ${CYAN}$DCIP${NC}..."
manspider "$DCIP" -d "$DOMAIN" -u "$USERNAME" -p "$PASSWORD" --sharenames SYSVOL -f Registry -e pol > /dev/null 2>&1

# =============================
# Step 1: Find registry.pol
# =============================
echo -e "${BLUE}[*] Step 1:${NC} Searching for Registry.pol files in ${CYAN}$LOOT_DIR${NC}..."
FILE=$(find "$LOOT_DIR" -type f -iname '*Registry.pol' | head -n1)
if [[ -z "$FILE" ]]; then
    echo -e "${YELLOW}[!] No Registry.pol file found.${NC}"
    exit 1
fi

# =============================
# Step 2: Dump contents
# =============================
echo -e "${BLUE}[*] Step 2:${NC} Dumping policy contents with regpol..."
TMPFILE=$(mktemp)
/root/.local/bin/regpol "$FILE" > "$TMPFILE"

# =============================
# Step 3: Filter WSUS policy strings
# =============================
echo -e "${BLUE}[*] Step 3:${NC} Filtering for WSUS policy strings..."
encoded_lines=$(cat "$TMPFILE" | grep -iaA5 'Software\\Policies\\Microsoft\\Windows\\WindowsUpdate' | grep -ia data | grep -ia "b'h" | sort -uV | cut -d"'" -f2)

# =============================
# Step 4: Display extracted WSUS URLs
# =============================
echo -e "${BLUE}[*] Step 4:${NC} Displaying extracted WSUS URLs..."

if [[ -z "$encoded_lines" ]]; then
    echo -e "${RED}[!] Either manspider failed to collect Registry.pol properly or no WSUS URLs were found in the policy.${NC}"
    rm -f "$TMPFILE"
    exit 0
fi

while IFS= read -r raw_url; do
    if [[ -n "$raw_url" ]]; then
        echo -e "    ${GREEN}[WSUS]${NC} $raw_url"
    else
        echo -e "    ${RED}[!] Failed to clean:${NC} $raw_url"
    fi
    echo
done <<< "$encoded_lines"

# Cleanup
rm -f "$TMPFILE"
