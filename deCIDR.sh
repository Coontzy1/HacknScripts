#!/bin/bash

# 2024-05-08 Austin Coontz @ #1
# 2025-01-07 - Updated to fix rounding errors and beautified? 
# You are going to need nmap installed ;)
# Run the script with ./deCIDR.sh to see usage and notes

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

trap f_SOMETHING_WENT_WRONG SIGHUP SIGINT SIGTERM SIGQUIT
f_SOMETHING_WENT_WRONG() {
    echo
    echo -e "${RED}Hopefully you pressed Ctrl + C | If not, something went wrong [>_<]${RESET}"
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
        if [ ! -f $arg ]; then echo -e "Something is wrong with ${RED}$arg${RESET} --> is it even a file?" && exit 1; fi # Checking if argument provided is a file.
        while read line; do f_process_IP $line; done < $arg #passing argument (files) to while loop 
    done

    sort -uV deCIDRd.tmp >> deCIDRd.out # sorting unique + IP Version Order
    rm deCIDRd.tmp #removing tmp file

    echo "IP's have been deCIDRd into deCIDRd.out - Goodluck ;)"
    echo -e "They're currently in a SORTED order. Make sure to randomize them with ${RED} sort -R ${PWD}/deCIDRd.out${RESET}"
}

f_process_IP () { 

    if echo $1 | grep -q '/'; then
        cidr=$(echo "$1" | cut -d'/' -f2)
        if [[ $cidr == "31" || $cidr == "32" ]]; then
            nmap -n -sL "$1" | sed '1d;$d' | cut -d' ' -f5 >> deCIDRd.tmp # Handle /31 and /32 directly 1 or 2 IPs
        else
            nmap -n -sL "$1" | sed '1,2d;$d;N;$d' | cut -d' ' -f5 >> deCIDRd.tmp #Handle normal CIDR ranges, cutting off network/broadcast
        fi
    elif echo $1 | grep -q '-' && ! echo $1 | grep -q '[a-zA-Z]' ; then # Checking for range with a -
        nmap -n -sL $1 | sed '1d;$d;' | cut -d' ' -f5 >> deCIDRd.tmp
    else 
        echo $1 >> deCIDRd.tmp
    fi
}

main $@
