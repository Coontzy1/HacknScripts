#!/bin/bash

# You are going to need nmap installed ;)  
# Hahahahahaha 2024-05-08 Austin Coontz @ #1
# Run the script with ./deCIDR.sh to see usage and notes

#Colors
BOLD="\033[1m"
RESET="\033[0m"

trap f_SOMETHING_WENT_WRONG SIGHUP SIGINT SIGTERM SIGQUIT
f_SOMETHING_WENT_WRONG () {
    echo
    echo "Something went wrong <<<<<<<<<<<<>>>>>>>>>>>>>" 
    exit 1
}

f_banner() {
    echo "U29vb29vb28uLi4uIHlvdSB3YW5uYSB1c2UgbXkgdG9vbCBhbmQgbm90IG1ha2UgeW91ciBvd24K"
    echo
    echo "Your input files can be IPs, hostnames, IP ranges and CIDR blocks."
    echo "Run with no arguments for more information: $0"
    echo
    
}

main () { #main
    
    if [ $# -eq 0 ]; then # If no arguments are provided
        echo "Usage: $0 <file1> <file2>..."
        echo "Example: $0 hostlist.txt list_of_CIDR.txt IP_ranges.txt"
        echo
        echo "Hostnames are not translated to IP addresses and will be passed to output file"
        echo "DNS resolution for these hostsnames should be done prior to this list"
        echo "If you give an IP range like 192.168.0.1-6 it will give you .1-.6"
        echo "This means 192.168.0.0-7 gives you .0 (network) and .7 (broadcast)"
        exit 1
    fi

    f_banner

    for arg in "$@"; do #loops over every argument passed to the script 

        if [ ! -f $arg ]; then echo -e "Something is wrong with ${BOLD}$arg${RESET} is it even a file?" && exit 1; fi #File checking

        while read line; 
        do f_process_IP $line
        done < $arg #passing arg to while loop 
    
    done

    sort -uV deCIDRd.tmp >> deCIDRd.out
    rm deCIDRd.tmp

    echo "IP's have been deCIDRd into deCIDRd.out"
    echo "They're currently in a SORTED order. Make sure to rando them"
    echo "Goodluck ;)"
}

f_process_IP () { 

    if echo $1 | grep -q '/'; then #filtering if it finds a '/' assunming that this is a CIDR range X.X.X.X/YY ALSO this totally doesn't work for a /31 and /32 because of subnets #pog
        nmap -n -sL $1 | sed '1,2d;$d;N;$d' | cut -d' ' -f5 >> deCIDRd.tmp

    elif 
        echo $1 | grep -q '-' && ! echo $1 | grep -q '[a-zA-Z]' ; then # If !CIDR, checking if there is a dash range that is not a hostname with -
        nmap -n -sL $1 | sed '1d;$d;' | cut -d' ' -f5 >> deCIDRd.tmp

    else 
        echo $1 >> deCIDRd.tmp
    fi

}

main $@
