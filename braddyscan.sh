#!/bin/bash

#This is my work in progress nmap/http enumeration/low hanging fruit scan for TryHackMe CTF's
#This is runs nmap -p- -T5 $ip Grabs the open ports and runs -A against just the open ports then runs an added recursive scan of all open http ports
#This script is meant to work with the standard tools that come on the attack box of TryHackMe. With no requirements to install anything else. 
#Ideas to come ftp auto pulldown files for anonymous login and subdomain enumeration 

									##########################################################
									##########################################################
									#####################Braddyscan v2.0######################
									##########################################################
									##########################################################

#Stops script when any command fails (errors, unset variables, and pipeline failures)

set -euo pipefail 

#Ask what IP I wanna scan and saves the output as IP

read -p "Enter IP Address:" IP

#Check to see if IP is even entered first if not exits -z mean "if 0" 


if [ -z "$IP" ]; then
	echo "No IP address entered. Exiting."
	exit 1 
fi

echo "Starting the nmap scan. Give me a second please....."


#Okay this is a lot so here we go runs nmap blazing fast then grabs the open ports using a grep regex expression matching 1-5 digit numbers followed by /open then removes the new line replacing with comma and then removing the comma at the end. 

PORTS=$(nmap -T5 -p- --open -oG - $IP | grep -oE '[0-9]{1,5}/open' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

#This checks to see if the ports are open and if no ports were found prints it and exits

if [ -z "$PORTS" ]; then
	echo "No open ports found on $IP."
	exit 0
fi

echo "Open ports: $PORTS"


#Do a detailed scan of open ports

echo "Preforming a deep scan of ports on $IP and saving it as nmap_scan_$IP.txt"
nmap -p $PORTS -sVC -O -oN "nmap_scan_$IP.txt" $IP

#Check for HTTP in the results of the scan 

echo "Checking to see if I can run a gobuster scan....."

#Similar to $PORTS except checking for http the \s+ means one or more spaces | means or in the regex expression 
	
HTTP_PORTS=$(grep -E "^[0-9]+/tcp\s+open\s+http[^ ]*|^[0-9]+/tcp\s+open\s+https[^ ]*" "nmap_scan_$IP.txt" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ' ')

#Had some whitespace this removes it

HTTP_PORTS=$(echo "$HTTP_PORTS" | xargs)

#Checks to see if there were any http to scan

if [ -z "$HTTP_PORTS" ]; then
	echo "No gobuster for you!! Check your nmap scan for futher enumeration."
	echo "Wait are you sure you entered the right ip??"
	exit 0
fi

#Debuggin 

echo "DEBUG: HTTP_PORTS='$HTTP_PORTS'" #DEBUGING BUT MIGHT KEEP

read -p "Enter wordlist path (Press enter for /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt): " WORDLIST
WORDLIST=${WORDLIST:-/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt}
if [ ! -f "$WORDLIST" ]; then
    echo "Wordlist not found: $WORDLIST"
    exit 1
fi

read -p "How deep should I look? Default 3: " DEPTH
DEPTH=${DEPTH:-3}


#The queue ensures full recursive scan *hopefully* :facepalm:

queue=()

#First-level Gobuster scan
for PORT in $HTTP_PORTS; do
    BASE_URL="http://$IP:$PORT"
    OUTPUT_FILE="braddyscan_${IP}_${PORT}.txt"

    echo "Starting scan on: $BASE_URL"
    gobuster dir --no-color -t 100 -u "$BASE_URL" -w "$WORDLIST" -o "$OUTPUT_FILE" -x php

    #Extract directories and adds them to the queue for recursive scanning

    while IFS= read -r DIR; do
        #Extract only the clean directory name
        CLEAN_DIR=$(echo "$DIR" | awk '{print $1}' | sed -E 's|//+|/|g' | tr -d '\r')

        if [[ ! -z "$CLEAN_DIR" ]]; then
            FULL_URL="${BASE_URL}${CLEAN_DIR}"
            queue+=("$FULL_URL")
        fi
    done < <(grep -E "301|302" "$OUTPUT_FILE" | awk -F '[ ]' '{print $1}')

    echo "DEBUG: Found directories at level 1: ${queue[*]}"
done

#DEBUG: Show initial queue
echo "DEBUG: Initial Queue (before recursion): ${queue[*]}"

#BFS-style recursion using the queue
CURRENT_DEPTH=1

while [ ${#queue[@]} -gt 0 ] && [ "$CURRENT_DEPTH" -le "$DEPTH" ]; do
    echo "DEBUG: Queue size: ${#queue[@]} | Current Depth: $CURRENT_DEPTH"

    next_level_dirs=()

    for URL in "${queue[@]}"; do
        OUTPUT_FILE="braddyscan_$(echo "$URL" | sed 's|[/:]|_|g').txt"

        echo "Scanning: $URL (Depth: $CURRENT_DEPTH)"
        gobuster dir --no-color -t 100 -u "$URL" -w "$WORDLIST" -o "$OUTPUT_FILE" -x php

        #Extract subdirectories and queue them for deeper scanning
        while IFS= read -r DIR; do
            CLEAN_DIR=$(echo "$DIR" | awk '{print $1}' | sed -E 's|//+|/|g' | tr -d '\r')

            if [[ ! -z "$CLEAN_DIR" ]]; then
                FULL_URL="${URL}${CLEAN_DIR}"
                next_level_dirs+=("$FULL_URL")
            fi
        done < <(grep -E "301|302|405" "$OUTPUT_FILE" | awk -F '[ ]' '{print $1}')

        echo "DEBUG: Directories found at depth $CURRENT_DEPTH: ${next_level_dirs[*]}"
    done

    #Move deeper into directories
    queue=("${next_level_dirs[@]}")
    ((CURRENT_DEPTH++))
done

echo "Braddy's recursive scan is complete."