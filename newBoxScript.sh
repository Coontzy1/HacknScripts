#!/bin/bash
# :triangle: WARNING - This uses rustscan. If you do not have it gg go next
# This script was made to run in Kali using qterminal -- Meaning it uses default wordlists and qterminal commands with xdotool
# Seems to be a problem with web shit and probably need to make a delay between things..........


# COLORS
RED='\033[0;31m'
BLUE='\033[1;34m'
RESET='\033[0m'

main() {
    f_banner #banner
    if [ "$UID" -ne 0 ]; then f_print_red "Run this script as sudo. Rustscan also needs to be installed as root because of nmap ports and stupid PATHs" && exit 1; fi #testing for permissions
    read -s -p "Enter sudo password: " sudoPassword #reading in sudo password
    echo
    read -p "Enter IP Address: " IP #reading in IP address
    read -p "Enter hostname, if you don't know it press [Enter]: " HOSTNAME 
    f_rename_tab SCRIPT

    xdotool key Ctrl+Shift+T; sleep 0.5
    xdotool type --delay 15 "sudo /home/kali/.cargo/bin/rustscan --ulimit 8192 -a $IP -r 1-65535 -- -sSVC -T5 | tee -a RUSTSCAN.OUTPUT123"; xdotool key Return
    xdotool type --delay 15 --clearmodifiers "$sudoPassword"; xdotool key Return
    f_rename_tab "SCANNING"

    f_split_vertically
    sleep 2.5
    xdotool type --delay 15 "sudo nmap -sU $IP -F"; xdotool key Return
    xdotool type --delay 15 --clearmodifiers "$sudoPassword"; xdotool key Return
    
    sleep 15
    if grep -q "Open $IP:445$" RUSTSCAN.OUTPUT123 ; then f_smb_enum; fi #SMB 
    if grep -q "Open $IP:21$" RUSTSCAN.OUTPUT123 ; then f_ftp_enum; fi #FTP

    # These need some type of delay in between because runs too quickly
    if grep -q "Open $IP:80$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum 80; fi #HTTP
    if grep -q "Open $IP:443$" RUSTSCAN.OUTPUT123 ; then sleep 5 && f_http_enum 443; fi #HTTP
    if grep -q "Open $IP:8080$" RUSTSCAN.OUTPUT123 ; then sleep 5 &&  f_http_enum 8080; fi #HTTP
    if grep -q "Open $IP:8000$" RUSTSCAN.OUTPUT123 ; then sleep 5 &&  f_http_enum 8000; fi #HTTP
    
    

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
    f_print_red "If you didn't get many results, try switching wordslists."

    if [ -n "$HOSTNAME" ]; then
        xdotool key Ctrl+Shift+T; sleep 0.1
        xdotool type --delay 15 "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://$IP:$1 -H "Host: FUZZ.$HOSTNAME" -mc all -ac"
        xdotool key Return
        f_rename_tab "VHosts"
    fi

    xdotool key Ctrl+Shift+T; sleep 0.1
    xdotool type --delay 15 "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$IP:$1/FUZZ"
    xdotool key Return
    f_rename_tab "Directories"

    
    xdotool key Ctrl+Shift+T; sleep 0.1
    xdotool type --delay 15 "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://$IP:$1/FUZZ"
    xdotool key Return
    f_rename_tab "Files"

}

main
