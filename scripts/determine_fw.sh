#!/bin/bash

# Usage: ./determine_fw.sh <target_ip_or_hostname> <spoof_ip_list_file>

TARGET=$1
SPOOF_LIST=$2

if [[ -z "$TARGET" || -z "$SPOOF_LIST" ]]; then
  echo "Usage: $0 <target_ip_or_hostname> <spoof_ip_list_file>"
  exit 1
fi

echo "Step 1: Basic SYN scan to check open/filtered ports on $TARGET"
SYN_OUTPUT=$(nmap -sS -p- -T4 $TARGET)
echo "$SYN_OUTPUT" | grep -E "open|filtered|closed"


echo -e "\n[*] Interpretation of results:"
echo "$SYN_OUTPUT" | grep "/tcp" | while read -r line; do
  PORT=$(echo "$line" | awk '{print $1}')
  STATE=$(echo "$line" | awk '{print $2}')
  
  case $STATE in
    open)
      echo "Port $PORT is open: The target is accepting TCP connections on this port."
      ;;
    closed)
      echo "Port $PORT is closed: The port is reachable but no service is listening."
      ;;
    filtered)
      echo "Port $PORT is filtered: Packets are blocked by a firewall or filtering device, and no response was received."
      ;;
    *)
      echo "Port $PORT state is $STATE: Unusual or unknown state."
      ;;
  esac
done

echo -e "\nStep 2: ACK scan to detect firewall statefulness on $TARGET"
ACK_OUTPUT=$(nmap -sA -p- -T4 $TARGET)
echo "$ACK_OUTPUT" | grep -E "filtered|unfiltered"

echo -e "\n[*] Interpretation of ACK scan:"
echo "$ACK_OUTPUT" | grep "/tcp" | while read -r line; do
  PORT=$(echo "$line" | awk '{print $1}')
  STATE=$(echo "$line" | awk '{print $2}')
  if [[ "$STATE" == "unfiltered" ]]; then
    echo "$PORT likely reachable (RST received) — might be stateless firewall or none"
  elif [[ "$STATE" == "filtered" ]]; then
    echo "$PORT is filtered — stateful firewall blocking unsolicited ACKs"
  else
    echo "$PORT state is unclear"
  fi
done


echo -e "\nStep 3: Spoofed source IPs test using $SPOOF_LIST"
while read -r SPOOF_IP; do
  echo -e "\n[>] Testing with spoofed IP: $SPOOF_IP"
  SPOOF_OUT=$(nping -c 3 --delay 1 -p 22 --tcp --source-ip $SPOOF_IP $TARGET 2>&1)
  if echo "$SPOOF_OUT" | grep -q "Received = 0"; then
    echo "[*] No replies — spoofed packets likely blocked or no response."
  else
    echo "[*] Replies received — target may accept spoofed traffic!"
  fi
done < "$SPOOF_LIST"

echo -e "\nStep 4: UDP scan with version detection on all UDP ports for $TARGET"
UDP_OUTPUT=$(nmap -sU -sV --top-ports 1000 $TARGET)
echo "$UDP_OUTPUT" | grep -E "open|filtered|closed"


echo -e "\n[*] Interpretation of UDP scan results:"
echo "$UDP_OUTPUT" | grep "/udp" | while read -r line; do
  PORT=$(echo "$line" | awk '{print $1}')
  STATE=$(echo "$line" | awk '{print $2}')
  SERVICE=$(echo "$line" | awk '{print $3}')
  VERSION=$(echo "$line" | cut -d' ' -f4-)

  case $STATE in
    open)
      echo "Port $PORT ($SERVICE) is open: The UDP service is responding and identified as:$VERSION"
      ;;
    open|filtered)
      echo "Port $PORT ($SERVICE) is open|filtered: No response or filtered by firewall; could be open or blocked."
      ;;
    closed)
      echo "Port $PORT ($SERVICE) is closed: The port is reachable but no service is listening."
      ;;
    filtered)
      echo "Port $PORT ($SERVICE) is filtered: Packets are blocked by firewall or filtering device."
      ;;
    *)
      echo "Port $PORT ($SERVICE) state is $STATE: Unusual or unknown state."
      ;;
  esac
done


echo -e "\n[✓] All tests completed."
