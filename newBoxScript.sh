#!/bin/bash

# COLORS
RED='\033[0;31m'
RESET='\033[0m'

# Print Red Text Function
print_red() {
    local text="$1"
    echo -e "${RED}${text}${RESET}"
}

print_red "Enter IP Address or Hostname"
read IP

echo "Enter Sudo Password:"
read -s SudoPassword  # Use -s to hide input (silent)

renameTab() {
    local title_text="$1"
    xdotool key --clearmodifiers Alt+Shift+s
    sleep 0.5
    xdotool type --delay 50 "$title_text"
    xdotool key Return
}

echo "Do you wanna NMAP scan stuff? [y/n]"
read NMAP

if [ "$NMAP" == "y" ]; then

    xdotool key Ctrl+Shift+T
    xdotool type --delay 50 "sudo nmap -p- $IP"
    xdotool key Return
    xdotool type --delay 50 --clearmodifiers "$SudoPassword"
    xdotool key Return
    renameTab "QuickScan"

    xdotool key Ctrl+Shift+T
    xdotool type --delay 50 "sudo nmap -sSVC $IP -p-"
    xdotool key Return
    xdotool type --delay 50 --clearmodifiers "$SudoPassword"
    xdotool key Return
    renameTab "FullScan"
 
    xdotool key Ctrl+Shift+T
    xdotool type --delay 50 "sudo nmap -sU $IP -F"
    xdotool key Return
    xdotool type --delay 50 --clearmodifiers "$SudoPassword"
    xdotool key Return
    renameTab "UDPScan"

else
  echo "Skipped NMAP scans"
fi

echo "Is there a web port open? [y/n]"
read webPortOpen

# FFUF SCANS FOR DIRECTORIES AND VHOSTS
if [ "$webPortOpen" == "y" ]; then
    echo "Which Port?"
    read PORT
    
    xdotool key Ctrl+Shift+T
    xdotool type --delay 50 "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$IP:$PORT/FUZZ"
    xdotool key Return
    renameTab "Directories"
    
    xdotool key Ctrl+Shift+T
    xdotool type --delay 50 "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://FUZZ.$IP:$PORT"
    xdotool key Return
    renameTab "VHosts"

    xdotool key Ctrl+Shift+T
    xdotool type --delay 50 "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://$IP:$PORT/FUZZ"
    xdotool key Return
    renameTab "Files"

else
    echo "No web port open. Skipping additional scans."
fi
