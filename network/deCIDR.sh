#!/bin/bash
# =============================================================================
# NAME        : deCIDR.sh
# DESCRIPTION : Expandos the IP Blocks and Stuffs into IPS :]!
# AUTHOR      : Austin Coontz
# DATE CREATED: 2025-03-12
# =============================================================================
# EDIT HISTORY:
# DATE                 | EDITED BY     | DESCRIPTION OF CHANGE
# ---------------------|---------------|----------------------------------------
# 2024-05-08           | Austin Coontz | Initial Creation
# 2025-01-07 11:29     | Austin Coontz | Fixed rounding errors? IDK 
# 2025-03-12 11:30     | Austin Coontz | Banner Change
# =============================================================================
# You are going to need nmap installed
# Run the script to see usage
# TODO:
# Could add in the redirected output (wihtout the -n) to see DNS names in a log file with -oA
# Colors
BLUE='\033[38;5;14m'
RED='\033[38;5;9m'
GREEN='\033[38;5;10m'
YELLOW='\033[38;5;11m'
PINK='\033[38;5;13m'
NC='\033[0m'

trap f_SOMETHING_WENT_WRONG SIGHUP SIGINT SIGTERM SIGQUIT
f_SOMETHING_WENT_WRONG() {
    echo
    echo -e "${RED}Hopefully you pressed Ctrl + C | If not, something went wrong [>_<]${NC}"
    exit 1 
}

f_banner() {
    echo "Usage: $0 <file1> <file2>..."
    echo "Example: $0 hostlist.txt list_of_CIDR.txt IP_ranges.txt"
    echo
    echo "Hostnames + single IP address are passed into .out file"
    echo "If you give an IP range like 192.168.0.1-6 it will give you .1-.6"
    echo "This means 192.168.0.0-7 gives you .0 (network) and .7 (broadcast)"
    echo "However, this rounds off the broadcast/network addresses for all CIDR except 31 or 32"
    exit 1
}

main () { #main
    
    current_dir=$PWD
    
    if [ $# -eq 0 ]; then # If no arguments are provided
        f_banner
    fi

    for arg in "$@"; do #loops over every argument passed to the script 
        if [ ! -f $arg ]; then echo -e "Something is wrong with ${RED}$arg${NC} --> is it even a file?" && exit 1; fi # Checking if argument provided is a file.
        while read line; do f_process_IP $line; done < $arg #passing argument (files) to while loop 
    done

    sort -uV deCIDRd.tmp >> deCIDRd.out # sorting unique + IP Version Order
    rm deCIDRd.tmp #removing tmp file

    echo "IP's have been deCIDRd into deCIDRd.out - Goodluck ;)"
    echo -e "They're currently in a SORTED order. Make sure to randomize them with ${RED} sort -R ${PWD}/deCIDRd.out${NC}"
}

f_process_IP () {
    if echo "$1" | grep -q '/'; then
        cidr=$(echo "$1" | cut -d'/' -f2)
        if [[ "$cidr" == "31" || "$cidr" == "32" ]]; then
            nmap -n -sL "$1" | sed '1d;$d' | cut -d' ' -f5 >> deCIDRd.tmp # Handle /31 and /32 directly (1 or 2 IPs)
        else
            nmap -n -sL "$1" | sed '1,2d;$d;N;$d' | cut -d' ' -f5 >> deCIDRd.tmp # Handle normal CIDR ranges (cutting off network/broadcast)
        fi
    elif echo "$1" | grep -q '-' && ! echo "$1" | grep -q '[a-zA-Z]'; then
        if echo "$1" | grep -qE '([0-9]+\.){3}[0-9]+-([0-9]+\.){3}[0-9]+'; then
            # Full IP range like 10.0.0.0-10.0.0.15 detected
            start_ip=$(echo "$1" | cut -d'-' -f1)
            end_ip=$(echo "$1" | cut -d'-' -f2)

            ip_to_int() {
                IFS=. read -r a b c d <<< "$1"
                echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
            }

            int_to_ip() {
                local ip=$1
                echo "$(( (ip >> 24) & 0xFF )).$(( (ip >> 16) & 0xFF )).$(( (ip >> 8) & 0xFF )).$(( ip & 0xFF ))"
            }

            start_int=$(ip_to_int "$start_ip")
            end_int=$(ip_to_int "$end_ip")

            if [ "$start_int" -gt "$end_int" ]; then
                echo -e "${RED}Invalid range: $start_ip is greater than $end_ip${NC}"
                return
            fi

            for ((i=start_int; i<=end_int; i++)); do
                int_to_ip "$i" >> deCIDRd.tmp
            done
        else
            # Shortened range like 10.0.0.1-15 handled by nmap
            nmap -n -sL "$1" | sed '1d;$d;' | cut -d' ' -f5 >> deCIDRd.tmp
        fi
    else
        echo "$1" >> deCIDRd.tmp
    fi
}


main $@
