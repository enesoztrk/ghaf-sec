#!/bin/bash

# Check if a target was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <target_ip_or_hostname>"
  exit 1
fi

# Assign the first argument as the target
TARGET="$1"

# Port range to scan
PORTS="22,53,9000,9010"

# Speed setting
SPEED="T4"


echo "Starting  Nmap scans on $TARGET..."

echo -e "\n================================="
echo -e "|    EXOTIC SCAN                |"
echo -e "================================="

# FIN scan
echo -e "\n[+] FIN Scan (-sF)"
nmap -sFV -p$PORTS -$SPEED $TARGET

# NULL scan
echo -e "\n[+] NULL Scan (-sN)"
nmap -sNV -p$PORTS -$SPEED $TARGET

# Xmas scan
echo -e "\n[+] Xmas Scan (-sX)"
nmap -sXV -p$PORTS -$SPEED $TARGET

# Maimon scan
echo -e "\n[+] Maimon Scan (-sM)"
nmap -sMV -p$PORTS -$SPEED $TARGET

# Window scan
echo -e "\n[+] Window Scan (-sW)"
nmap -sWV -p$PORTS -$SPEED $TARGET

echo -e "\nScan complete."
