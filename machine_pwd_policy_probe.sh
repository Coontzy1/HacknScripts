#!/usr/bin/env bash
set -euo pipefail

G='\033[1;32m'; Y='\033[1;33m'; B='\033[1;34m'; R='\033[1;31m'; N='\033[0m'

usage() {
  cat <<EOF
Usage:
  $(basename "$0") -dc-ip <IP> -d <DOMAIN> -u <USER> (-p <PASS> | -H <LM:NT>) [-l <lootdir>]
EOF
  exit 1
}

DCIP=""; DOMAIN=""; USER=""; PASS=""; HASH=""; LOOT="./loot_sysvol"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -dc-ip|--dc-ip) shift; DCIP="${1:-}";;
    -d|--domain) shift; DOMAIN="${1:-}";;
    -u|--user|--username) shift; USER="${1:-}";;
    -p|--pass|--password) shift; PASS="${1:-}";;
    -H|--hash) shift; HASH="${1:-}";;
    -l|--loot) shift; LOOT="${1:-}";;
    -h|--help) usage;;
    *) echo -e "${R}[-] Unknown arg:${N} $1"; usage;;
  esac
  shift || true
done

[[ -z "$DCIP" || -z "$DOMAIN" || -z "$USER" ]] && usage
if [[ -z "${PASS}${HASH}" ]]; then
  echo -e "${R}[-] Provide -p <password> or -H <LM:NT>${N}"; exit 1
fi
if [[ -n "$PASS" && -n "$HASH" ]]; then
  echo -e "${R}[-] Use either -p or -H, not both.${N}"; exit 1
fi

command -v manspider >/dev/null 2>&1 || { echo -e "${R}[-] manspider not found${N}"; exit 1; }
mkdir -p "$LOOT"

CSV="${LOOT%/}/machine_pwd_policy_summary.csv"
: > "$CSV"
echo "GPO_ID,Setting,Value,SourceFile" >> "$CSV"

echo
echo -e "${B}[*] Looting SYSVOL to:${N} $LOOT"

# ---- manspider: GptTmpl.inf ----
if [[ -n "$PASS" ]]; then
  CMD_INF=(manspider "$DCIP" -d "$DOMAIN" -u "$USER" -p "$PASS" --sharenames SYSVOL -e inf -l "$LOOT")
else
  CMD_INF=(manspider "$DCIP" -d "$DOMAIN" -u "$USER" -H "$HASH" --sharenames SYSVOL -e inf -l "$LOOT")
fi
echo -e "${Y}[+] MANSPIDER command executed:${N} ${CMD_INF[*]}"
"${CMD_INF[@]}"

# ---- manspider: Registry.xml ----
if [[ -n "$PASS" ]]; then
  CMD_XML=(manspider "$DCIP" -d "$DOMAIN" -u "$USER" -p "$PASS" --sharenames SYSVOL -e xml -l "$LOOT")
else
  CMD_XML=(manspider "$DCIP" -d "$DOMAIN" -u "$USER" -H "$HASH" --sharenames SYSVOL -e xml -l "$LOOT")
fi
echo -e "${Y}[+] MANSPIDER command executed:${N} ${CMD_XML[*]}"
"${CMD_XML[@]}"

gpo_from_path() {
  local p="$1" g=""
  g="$(echo -n "$p" | grep -aoE '\{[0-9A-Fa-f-]{36}\}' | head -n1 | tr -d '{}')" || true
  if [[ -z "$g" ]]; then
    g="$(echo -n "$p" | grep -aoE 'Policies_([0-9A-Fa-f]{32,36})' | head -n1 | sed -E 's/^Policies_//')" || true
  fi
  [[ -n "$g" ]] && echo "$g" || echo "UNKNOWN"
}

# UTF-16LE → UTF-8 (fallback to cat if already UTF-8)
read_inf_utf8() {
  local f="$1"
  if iconv -f UTF-16LE -t UTF-8 "$f" >/dev/null 2>&1; then
    iconv -f UTF-16LE -t UTF-8 "$f"
  else
    cat "$f"
  fi
}

found_any=0
found_disable=0
found_maxage=0
found_refuse=0
export LC_ALL=C

echo -e "${B}[*] Parsing Security Options (.inf) for Netlogon settings…${N}"
while IFS= read -r -d '' inf; do
  gpo="$(gpo_from_path "$inf")"
  while IFS= read -r line; do
    if [[ "$line" =~ Netlogon\\Parameters\\DisablePasswordChange[[:space:]]*=[[:space:]]*4,([0-9]+) ]]; then
      val="${BASH_REMATCH[1]}"
      echo "$gpo,DisablePasswordChange,$val,$inf" >> "$CSV"
      found_any=1; found_disable=1
      echo -e "  ${G}[+]${N} DisablePasswordChange=${Y}${val}${N} (GPO {${gpo}})"
    fi
    if [[ "$line" =~ Netlogon\\Parameters\\MaximumPasswordAge[[:space:]]*=[[:space:]]*4,([0-9]+) ]]; then
      val="${BASH_REMATCH[1]}"
      echo "$gpo,MaximumPasswordAge,$val,$inf" >> "$CSV"
      found_any=1; found_maxage=1
      echo -e "  ${G}[+]${N} MaximumPasswordAge=${Y}${val}${N} (GPO {${gpo}})"
    fi
  done < <(read_inf_utf8 "$inf" | tr -d '\r' | grep -aE 'Netlogon\\Parameters\\(DisablePasswordChange|MaximumPasswordAge)=' || true)
done < <(find "$LOOT" -type f -iname '*GptTmpl.inf' -print0)

echo -e "${B}[*] Parsing GPP Registry (Registry.xml) for RefusePasswordChange…${N}"
while IFS= read -r -d '' xml; do
  gpo="$(gpo_from_path "$xml")"
  while IFS= read -r props; do
    if [[ "$props" == *'key="SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"'* ]] \
       && [[ "$props" == *'name="RefusePasswordChange"'* ]]; then
      if [[ "$props" =~ value=\"([0-9A-Fa-f]{8})\" ]]; then
        hex="${BASH_REMATCH[1]}"; dec=$((16#$hex))
        echo "$gpo,RefusePasswordChange,$dec,$xml" >> "$CSV"
        found_any=1; found_refuse=1
        echo -e "  ${G}[+]${N} RefusePasswordChange=${Y}${dec}${N} (GPO {${gpo}})"
      fi
    fi
  done < <(grep -aPo '<Properties\b[^>]*/>' "$xml" || true)
done < <(find "$LOOT" -type f -iname '*_Preferences_Registry_Registry.xml' -print0)

# ---- Defaults if not set anywhere ----
# DisablePasswordChange absent -> 0
# MaximumPasswordAge absent -> 30
# RefusePasswordChange absent -> 0
if [[ "$found_disable" -eq 0 ]]; then
  echo -e "  ${Y}[~] DisablePasswordChange not defined in any GPO → effective default ${G}0${N}"
  echo "DEFAULT,DisablePasswordChange,0,(not defined in GPO)" >> "$CSV"
fi
if [[ "$found_maxage" -eq 0 ]]; then
  echo -e "  ${Y}[~] MaximumPasswordAge not defined in any GPO → effective default ${G}30${N}"
  echo "DEFAULT,MaximumPasswordAge,30,(not defined in GPO)" >> "$CSV"
fi
if [[ "$found_refuse" -eq 0 ]]; then
  echo -e "  ${Y}[~] RefusePasswordChange not defined in any GPO → effective default ${G}0${N}"
  echo "DEFAULT,RefusePasswordChange,0,(not defined in GPO)" >> "$CSV"
fi

if [[ "$found_any" -eq 0 ]]; then
  echo
  echo -e "${Y}[!] No matching settings found in ${LOOT}.${N} If you just changed GPOs, give DFSR/FRS + GPMC a minute to write/replicate."
fi

echo
echo -e "${G}[*] Wrote summary:${N} ${CSV}"
