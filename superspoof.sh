#!/bin/bash
# =============================================================================
# NAME        : superspoof.sh
# DESCRIPTION : Auto-get tenant info and domains with mx and spoofy them
# AUTHOR      : Austin Coontz
# DATE CREATED: 2025-05-01 16:32
# =============================================================================
# EDIT HISTORY:
# DATE                 | EDITED BY     | DESCRIPTION OF CHANGE
# ---------------------|---------------|----------------------------------------
# 2025-05-01 16:32     | Austin Coontz | Initial creation.
# 2025-05-16 13:37     | Austin Coontz | Uh fixing stuff #verbose
# =============================================================================
# Take domain name, find da other domains associated in Azure
# Gets the MX records out with digs and logs it
# Runs spoofy and logs that as well so you have pretty screenshots <3
# msftrecon github - https://github.com/Arcanum-Sec/msftrecon
# install with pipx install git+https://github.com/MattKeeley/Spoofy

# Colors
BLUE='\033[38;5;14m'
RED='\033[38;5;9m'
GREEN='\033[38;5;10m'
YELLOW='\033[38;5;11m'
PINK='\033[38;5;13m'
NC='\033[0m'

spoofy_file='/pentest/vulnerability-analysis/Spoofy/spoofy.py' # https://github.com/MattKeeley/Spoofy

f_banner () {
echo '                                                1010101010101011                                                
                                           101011              10101                                            
                                         010                        101                                         
                                      101                             101                                       
                                     01                                 010                                     
                                   101                                    10                                    
                                  01                                       10                                   
                                 10                                         10                                  
                                10                                           10                                 
                                01                                            11                                
                               10           101010            010101          00                                
                               10          01010101          10101010         111                               
                               01          10101010          01010101          01                               
                               10          1010101           1010101           11                               
                               01             10                11             01                               
                               10                                              11                               
                               01                                              01                               
                                                                                                                
       000000   000   001 0000000   00000000 10000001    000000   0000000    1000001   1000000   00000000       
      000000001 000   000 000000000 00000000 000000000 100000000  00000000  000000000 1000000001 00000000       
      000  0001 000   001 000   000 000      100   000 1001  100  000   001 000   000 100   0001 000            
      000       000   000 000   000 000      000   000 0001       000   001 000   000 100   1001 000            
      00000000  000   001 000000000 0000000  100000000 100000000  00000000  000   000 100   0001 0000000        
       11010001 000   000 00000001  000      00000000    1111000  00000001  000   000 100   0001 000            
      000  0001 000   001 000       000      100  000  1011  000  000       000   000 100   1001 000            
      000000001 000000000 000       00000000 000   001 100000000  000       000000000 1000000001 000            
       000000    0000000  000       00000000 100   000   000000   000        0000000   1000000   000            
                                                                                                                
                               10                                              01                               
                               01                                              11                               
                               10                                              01                               
                               01                                              11                               
                               10                                              01                               
                               01                                              11                               
                               10                                              01                               
                               01                                              11                               
                               10                                              01                               
                               01                                              11                               
                               10                                              01                               
                               01         010101                010101         11                               
                               10       10     10             101    011       01                               
                               01     10        101         101        011     11                               
                               10   101           011      01            01   01                                
                                10101               01010101               0101       '
}

f_SOMETHING_WENT_WRONG() {
    echo
    kill -9 ${MSFT_PID}
    echo -e "${RED}Either you pressed CTRL + C or you just yee'd your last haw."
    echo -e "Would you like to accompany me to dinner?"
    echo -e "That is, if you're not doing anything.${NC}"
    echo
    exit 1 
}
trap f_SOMETHING_WENT_WRONG SIGHUP SIGINT SIGTERM SIGQUIT

f_config_checks() {
    echo
    echo -e "[${YELLOW}!${NC}] This takes a minute to run because of air time restrictions (RFC 2549)"
    echo
    if [ -f "${spoofy_file}" ]; then
        echo -e "[${GREEN}+${NC}] Found spoofy.py"
    else
        echo -e "[${RED}!${NC}] Cannot find spoofy.py"
        exit 1
    fi

    if command -v msftrecon >/dev/null 2>&1; then
      if msftrecon -h | grep -q "Enumerates valid Microsoft 365 domains"; then
          echo -e "[${GREEN}+${NC}] msftrecon is installed and working"
      else
          echo -e "[${RED}!${NC}] msftrecon command found but not functioning correctly"
          exit 1
      fi
    else
        echo -e "[${RED}!${NC}] msftrecon not found in PATH"
        exit 1
    fi
}

fake_prompt() {
  GREEN='\033[1;38;5;10m'  # bold green
  CYAN='\033[1;38;5;14m'   # bold cyan
  RED='\033[1;38;5;9m'     # bold red
  NC='\033[0m'             # reset

  now=$(date "+%m-%d-%Y %T")
  ip=$(ip -o -4 addr | grep -v -E ': lo|: docker' | awk '{print $4}' | cut -d'/' -f1 | head -n1)
  user=$(whoami)

  # First line: timestamp, IP, user
  echo -e "${GREEN}[${now}]${NC}:${CYAN}[${ip}]${NC}:${RED}[${user}]${NC}"

  # Second line: fake prompt with command
  echo -e "${NC}[~] ${BOLD}$*${NC}"
}

f_makedir() {
    echo
    read -p "Enter domain name (Ex: domain.com): " domainName   
    dirName="spoofy_$(echo "${domainName}" | rev | cut -d'.' -f2- | rev)"                               
    if [ -d "${dirName}" ]; then #checking if dir already exists
        echo -e "${RED}Directory ${dirName} already exists... Exiting${NC}"
        exit 1
    else
        mkdir -p ${dirName}
        cd ${dirName}
        echo
    fi 
}

main () {
  f_banner # ok lary
  f_config_checks #checking da configs
  f_makedir #making da directories 

  msftrecon -d ${domainName} > ${domainName}.msftrecon.tee &
  
  MSFT_PID=$!

  spinner='|/-\'
  i=0
  echo  "Running..."
  # Loop to show spinner while python script runs
  while kill -0 "${MSFT_PID}" >/dev/null 2>&1; do
     i=$(( (i+1) %4 ))
     printf "\r%s" "${spinner:$i:1}"
     sleep 0.2
  done
  echo
  fake_prompt "msftrecon -d ${domainName}"
  cat ${domainName}.msftrecon.tee 
  echo

  # Parsing Stuff
  awk '/^\[\+\] Domains found:$/ {f=1; next} f && /^$/ {f=0} f' ${domainName}.msftrecon.tee | grep -v 'onmicrosoft.com' > potential_domains
  while read -r line; do mx=$(dig @8.8.8.8 +short "${line}" MX); [[ -n "$mx" ]] && echo "$line"; done < potential_domains > domains_with_mx_records
  while read -r line; do echo "dig @8.8.8.8 +short "${line}" MX"; dig @8.8.8.8 +short "${line}" MX; done < potential_domains > mx_record_dig.tee
  rm potential_domains

  while read -r line; do fake_prompt "python3 spoofy.py -d ${line}"; python3 /pentest/vulnerability-analysis/Spoofy/spoofy.py -d ${line} >> "${line}.spoofy.tee"; python3 /pentest/vulnerability-analysis/Spoofy/spoofy.py -d ${line}; done < domains_with_mx_records

}

main
