#!/bin/bash
# :triangle: WARNING - This uses rustscan. If you do not have it gg go next
# This script was made to run in Kali using qterminal -- Meaning it uses default wordlists and qterminal commands with xdotool
# This script will also need to run as SUDO but it uses passwordless sudo 

# TODO?
# add recrusive optioins..?

# COLORS
RED='\033[0;31m'
BLUE='\033[1;34m'
RESET='\033[0m'

main() {
    f_banner #banner
    if [ "$UID" -ne 0 ]; then f_print_red "Run this script as sudo. Rustscan also needs to be installed as root because of nmap ports and stupid PATHs" && exit 1; fi #testing for permissions

#    read -s -p "Enter sudo password: " sudoPassword #reading in sudo password

    echo
    read -p "Enter IP Address: " IP #reading in IP address
    read -p "Enter hostname, if you don't know it press [Enter]: " HOSTNAME 
    f_rename_tab SCRIPT

    xdotool key Ctrl+Shift+T; sleep 0.5
    xdotool type --delay 15 "sudo /home/kali/.cargo/bin/rustscan --ulimit 8192 -a $IP -r 1-65535 -- -sSVC -T5 | tee -a RUSTSCAN.OUTPUT123"; xdotool key Return
  #  xdotool type --delay 15 --clearmodifiers "$sudoPassword"; xdotool key Return
    f_rename_tab "SCANNING"

    f_split_vertically
    sleep 2.5
    xdotool type --delay 15 "sudo nmap -sU $IP -F"; xdotool key Return
  #  xdotool type --delay 15 --clearmodifiers "$sudoPassword"; xdotool key Return
    
    sleep 15
    if grep -q "Open $IP:445$" RUSTSCAN.OUTPUT123 ; then f_smb_enum; fi #SMB 
    if grep -q "Open $IP:21$" RUSTSCAN.OUTPUT123 ; then f_ftp_enum; fi #FTP

    # These need some type of delay in between because runs too quickly
    if [[ -z "$HOSTNAME" ]]; then
        if grep -q "Open $IP:80$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 80; fi # HTTP
        if grep -q "Open $IP:443$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 443; fi # HTTPS
        if grep -q "Open $IP:8080$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 8080; fi # Alternative HTTP
        if grep -q "Open $IP:8443$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 8443; fi # Alternative HTTPS
        if grep -q "Open $IP:8000$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 8000; fi # Alternative HTTP
        if grep -q "Open $IP:8888$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 8888; fi # Alternative HTTP
        if grep -q "Open $IP:8081$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 8081; fi # Alternative HTTP
        if grep -q "Open $IP:8082$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 8082; fi # Alternative HTTP
        if grep -q "Open $IP:8880$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 8880; fi # Alternative HTTP
        if grep -q "Open $IP:8181$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $IP 8181; fi # Alternative HTTP
    else
        if grep -q "Open $IP:80$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 80; fi # HTTP
        if grep -q "Open $IP:443$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 443; fi # HTTPS
        if grep -q "Open $IP:8080$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 8080; fi # Alternative HTTP
        if grep -q "Open $IP:8443$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 8443; fi # Alternative HTTPS
        if grep -q "Open $IP:8000$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 8000; fi # Alternative HTTP
        if grep -q "Open $IP:8888$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 8888; fi # Alternative HTTP
        if grep -q "Open $IP:8081$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 8081; fi # Alternative HTTP
        if grep -q "Open $IP:8082$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 8082; fi # Alternative HTTP
        if grep -q "Open $IP:8880$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 8880; fi # Alternative HTTP
        if grep -q "Open $IP:8181$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum $HOSTNAME 8181; fi # Alternative HTTP
    fi

    rm RUSTSCAN.OUTPUT123

}

f_print_red() { # Print Red Text Function
    local text="$1"
    echo -e "${RED}${text}${RESET}"
}

f_print_blue() { # Print Red Text Function
    local text="$1"
    echo -e "${BLUE}${text}${RESET}"
}

f_banner() {
    echo "
    ----------------================================================================================
    --------========================================================================================
    ======================================-------------=============================================
    ================================--::-.  .    .... ..:::---======================================
    =============================--:.......              ...::::-==++==++++=========================
    ===========================-::.  ..  ..      ..  ..:::...:....:-=+++++++++++++++++++++++++++++++
    ======++++++++++++++=-===--:.   ...   .     ......::.....:..  ..:-++++++++++++++++++++++++++++++
    +++++++++++++++++++++=:::::.. .::....::.....:.:...:::.:::::.  ....:-++++++++++++++++++++++++++++
    ++++++++++++++++++++==-:    .:.::.::::-:..::::::::.::::::...  .... .:=*****************+++++++++
    +++++++++++++***++++++=:.   .:-=-:-===--:::::::::::.::::... .....   .:-+************************
    +****************+=+=-:.  .:=++++==++++===------::::::::::.. ..      ..-************************
    ******************+--:.  .:-=******++++++++==-----::::--::::....     ..:*#*####*****************
    *****************++==-.. .-=+*######*******++==-=--::::::::::::::.   ..-########################
    ******##*########*+=--..::-++**###########**+++==---::-::.::::....  . .*########################
    ###################*+-:::-=+***############**+===---:::::..::......   .*########################
    ###################*+-:-::++++++==++**####**+=----====--::::--:.. .:..:#%%%%%%%%%%%%%%%%########
    #################%%#*+--::+++*****+++++*##*+=---==-==--=--====:.   ..:*%%%%%%%%%%%%%%%%%%%%%%%%%
    #######%%##%%%%%%%%%%#=:..+***+++=:==+*###*+++=+*=:-=-===++=+=-..:--.+%%%%%%%%%%%%%%%%%%%%%%%%%%
    ##%%%%%%%%%%%%%%%%%%%#=::.=#**++*==+**%###*++************++==+-:-.==+%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%%%%%%%%%%%%%%%%%%%%#**#==##########%%###*++**#####******+==+==-.:+%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%%%%%%%%%%%%%%%%%%%%%%%%%+*#########%####*+++**######****++=====--*@%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%%%%%%%%%%%%%%%%%%%%%%%%%%*#####%#########*=++=*#####***+++===+++*%@@@@@@@@@@@@%%%%%%%%%%%%%%%%
    %%%%%%%%%%%%%%%%%%%%%%%%%%%######%#**##***+======++****++++===-=*%@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%
    %%%%%%%%%%%%%%%%%%@@@@@@@@@%#####*+*###***++====+++==+*++++===::%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%
    %%%%%%%%%%%%%@@@@@@@@@@@@@@@####*=+*******##*++=====*##++++=== .%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    %%%%%%@@@@@@@@@@@@@@@@@@@@@@@*##*##***+******+++++**##*=++====:=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@%***########**+++++++****+++=====*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*+**##%#####**********+++==-=+: --*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#*+*#%%%#####******++===--==+- :: =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*++*#####**+++++==-----===+..=-  :*@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+==++=+***++===------====+=::==     .+%@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=.+-+#*==--:::::::----====-.-==.        :=+#%@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@%*+-:. .*--*#*++===--------===-.:-==.             .:-+#%@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@#+-..   .. +=.+****++++========-..-===.                   .:=*%@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@%*=:.  ....... =+ :******++++++===-:-====:                .....   .-*%@@@@@@@
    @@@@@@@@@@@@@@@@%*-.  ..........  ++. =**#****++++++=======-                 .........  .:=#@@@@
    @@@@@@@@@@@@%#+:.  ............. :**- .+******+*****++=====.           ...  ............    :=#@
    @@@@@@@@%#+-.   ................ +*=- .:**##****##+++=====-.                ................   :
    @@@@@#+-.   ............ ...... :=. =:.:+*##**###=. :===+=:.             ...................... 
    @@#=:.  ..............   ......   :-:=.:-*####%#=-:. .:==-. .     .....   .................. ...
    @+.  .........   ...    .......   ++==..:+#%%#%*--==. :-=- .      .  ....      ............. ...
    + ..........      ..    .......  .++++.-===*##%+===. -=++. .      .   ...     ...  .  .    .  ..
    : .........       ..    .......  :**++=++=+++#***=  =+++: .           .   ..                    
    .. .......       ..      ......  :***+++**+*+=-=: .=++*= .           .                          
    ..  .. ..        ..       .....  :*****+-++-:-===++*+*+.            .                           
    ..                         ....  :*****+=+==******++**-                                         
    .                          ....  :***++******++++++**=                                          
    .                           ...  -*++++**********++*+.                                          
    "
}

f_split_vertically() { # Splits terminal vertically
    xdotool key --clearmodifiers Ctrl+Shift+R
}

f_rename_tab() {
    xdotool key --clearmodifiers Alt+Shift+s
    sleep 0.5
    xdotool type --delay 15 "$1"
    xdotool key Return
}

f_smb_enum() {
    f_print_blue "Running SMB Enumeration..."
    xdotool key Ctrl+Shift+T
    xdotool type --delay 15 "echo -e '\033[1;31mANON ACCESS NETEXEC\033[0m' && netexec smb $IP -u '' -p '' && echo -e '\033[1;31mSMB SHARES NETEXEC\033[0m' && netexec smb $IP --shares -u '' -p '' && echo -e '\033[1;31mENUM4LINUX\033[0m' && enum4linux-ng $IP -A -C "
    xdotool key Return
    f_rename_tab "SMB :D"
}

f_ftp_enum() {
    f_print_blue "Running FTP Enumeration..."
    xdotool key Ctrl+Shift+T
    f_print_red "Potentially useful command: wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98 #Download all"
    xdotool type --delay 15 "nmap $IP --script ftp-* -p 21 -T5"
    xdotool key Return
    f_rename_tab "FTP :D"
}

f_http_enum() {
    f_print_blue "Running HTTP Enumeration..."

    if [ -n "$HOSTNAME" ]; then
        xdotool key Ctrl+Shift+T; sleep 0.2
        xdotool type --delay 15 "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://$1:$2 -H 'Host: FUZZ.$HOSTNAME' -mc all -ac"
        xdotool key Return
        f_rename_tab "VHosts"
    fi

    xdotool key Ctrl+Shift+T; sleep 0.2
    xdotool type --delay 15 "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$1:$2/FUZZ  -mc all -ac"
    xdotool key Return
    f_rename_tab "Directories"

    xdotool key Ctrl+Shift+T; sleep 0.2
    xdotool type --delay 15 "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://$1:$2/FUZZ -mc all -ac"
    xdotool key Return
    f_rename_tab "Files"

    if [ -n "$HOSTNAME" ]; then #Second VHOST Enum for finding references to subdomains within files 
        xdotool key Ctrl+Shift+T; sleep 0.2
        xdotool type --delay 15 "wget --mirror --convert-links --adjust-extension --page-requisites http://$HOSTNAME:$2/ && echo 'Cleanup Directory Needed\n Potential Subdomains:' && grep -roE '[a-zA-Z0-9-]+\.$HOSTNAME'"
        #xdotool type --delay 15 ""
        #xdotool type --delay 15 ""
        xdotool key Return
        f_rename_tab "VHosts2"
    fi

}

main
