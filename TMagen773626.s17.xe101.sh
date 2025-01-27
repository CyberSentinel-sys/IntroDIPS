#!/bin/bash

#=====================================================
# Script Name: Network Analysis and Mapping Script
# Author: Yechiel Said
# Date: 23/01/2025
# Version: 1.4
# Description:
# This script performs various network analysis tasks,
# including:
#   - Scanning for devices and their IP/MAC addresses
#   - Fetching router's internal and external IPs
#   - Displaying DNS, DHCP, and ISP information
#   - Identifying network protocols in use and their ports
#   - Providing WHOIS information for public IP
#   - Performing online lookups for captured ports
# All results are saved in the output file "network_info.txt".
#=====================================================

# Display Banner
function display_banner {
  echo "====================================================="
  echo "         Network Analysis and Mapping Script         "
  echo "====================================================="
  echo
}

# Install required tools
function install_required_tools {
  echo "[+] Checking and installing required tools..."
  required_tools=("nmap" "arp-scan" "tshark" "jq" "whois" "curl")
  for tool in "${required_tools[@]}"; do
    if ! command -v $tool &> /dev/null; then
      echo "    [*] $tool is not installed. Installing..."
      sudo apt-get install -y $tool
    else
      echo "    [*] $tool is already installed. Skipping installation."
    fi
  done
  echo "[+] All required tools are installed."
  echo
}

# Check if running as root
function check_root {
  if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root."
    exit
  fi
}

# Output file
function setup_output {
  output_file="network_info.txt"
  echo "[+] Setting up output file: $output_file"
  echo "Network and System Information" > $output_file
  echo "=============================" >> $output_file
  echo
}

# 1. Map the Network

# 1.1 Display Devices IP Address
function display_ip_addresses {
  echo "[+] Scanning for devices' IP addresses..."
  echo -e "\n1.1 Devices IP Addresses:" >> $output_file
  echo "----------------------------------" >> $output_file
  nmap -sn $(ip -o -f inet addr show | awk '/scope global/ {print $4}') >> $output_file
  echo "[+] Devices' IP addresses saved to output file."
  echo
}

# 1.2 Display Devices MAC Address and Vendor (partially displayed)
function display_mac_and_vendor {
  echo "[+] Scanning for devices' MAC addresses and vendors..."
  echo -e "\n1.2 Devices MAC Address and Vendor (partial):" >> $output_file
  echo "----------------------------------" >> $output_file
  arp-scan --localnet | awk '{print substr($0, 1, 50)}' >> $output_file
  echo "[+] Devices' MAC addresses and vendors saved to output file."
  echo
}

# 1.3 Display the Router's Internal and External IP Addresses (partially displayed)
function display_router_ips {
  echo "[+] Fetching router's internal and external IP addresses..."
  echo -e "\n1.3 Router's Internal and External IP Addresses (partial):" >> $output_file
  echo "----------------------------------" >> $output_file
  internal_ip=$(ip route | grep default | awk '{print $3}')
  external_ip=$(curl -s ifconfig.me)
  if [[ -z "$external_ip" ]]; then
    echo "Error: Unable to fetch external IP address." >> $output_file
  else
    echo "Router Internal IP: ${internal_ip}" >> $output_file
    echo "Router External IP: ${external_ip%.*}.XXX" >> $output_file
  fi
  echo "[+] Router IP addresses saved to output file."
  echo
}

# 1.4 Display Device Names
function display_device_names {
  echo "[+] Scanning for device names..."
  echo -e "\n1.4 Device Names:" >> $output_file
  echo "----------------------------------" >> $output_file
  nmap -sn $(ip -o -f inet addr show | awk '/scope global/ {print $4}') | grep "Nmap scan report for" >> $output_file
  echo "[+] Device names saved to output file."
  echo
}

# 1.5 Display the DNS and DHCP IP Addresses in your Network
function display_dns_and_dhcp {
  echo "[+] Fetching DNS and DHCP server information..."
  echo -e "\n1.5 DNS and DHCP IP Addresses:" >> $output_file
  echo "----------------------------------" >> $output_file
  nmcli dev show | grep 'IP4.DNS' | awk '{print "DNS Server: "$2}' >> $output_file
  echo "DHCP Server: $(cat /var/lib/dhcp/dhclient*.leases | grep dhcp-server-identifier | awk '{print $3}' | head -1)" >> $output_file
  echo "[+] DNS and DHCP information saved to output file."
  echo
}

# 1.6 Display your Internet Service Provider (ISP)
function display_isp {
  echo "[+] Fetching ISP information..."
  echo -e "\n1.6 Internet Service Provider (ISP):" >> $output_file
  echo "----------------------------------" >> $output_file
  isp=$(curl -s http://ip-api.com/json | jq -r '.isp')
  if [[ -z "$isp" ]]; then
    echo "Error: Unable to fetch ISP information." >> $output_file
  else
    echo "ISP: $isp" >> $output_file
  fi
  echo "[+] ISP information saved to output file."
  echo
}

# 1.7 Display if the Device is Connected via Ethernet or Wireless
function display_connection_type {
  echo "[+] Checking connection type..."
  echo -e "\n1.7 Connection Type (Ethernet or Wireless):" >> $output_file
  echo "----------------------------------" >> $output_file
  nmcli dev status | awk '{if(NR>1) print $1" - "$2}' >> $output_file
  echo "[+] Connection type saved to output file."
  echo
}

# 2. Collecting Information

# 2.1 Use Shodan to Check Your Public IP Address
function shodan_check {
  echo "[+] Displaying instructions to check public IP on Shodan..."
  echo -e "\n2.1 Shodan Check for Public IP:" >> $output_file
  echo "----------------------------------" >> $output_file
  echo "Visit https://shodan.io and check your public IP: ${external_ip}" >> $output_file
  echo "[+] Instructions saved to output file."
  echo
}

# 2.2 Use WHOIS to Check Who is Registered on Your Public IP Address
function whois_check {
  echo "[+] Fetching WHOIS information for public IP..."
  echo -e "\n2.2 WHOIS for Public IP Address:" >> $output_file
  echo "----------------------------------" >> $output_file
  if [[ -z "$external_ip" ]]; then
    echo "Error: External IP is unavailable. WHOIS lookup skipped." >> $output_file
  else
    whois $external_ip >> $output_file 2>/dev/null
    if [[ $? -ne 0 ]]; then
      echo "Error: WHOIS command failed for IP $external_ip." >> $output_file
    else
      echo "[+] WHOIS information saved to output file."
    fi
  fi
  echo
}

# 2.3 Sniff Your Network and Identify Top Ports
function sniff_top_protocols {
  echo "[+] Capturing network traffic and identifying top ports..."
  tshark -i eth0 -a duration:30 -T fields -e tcp.port -e udp.port | grep -o '[0-9]*' | sort -n | uniq > /tmp/captured_ports.txt
  echo -e "\n2.3 Network Protocol Ports in Use:" >> $output_file
  echo "----------------------------------" >> $output_file
  cat /tmp/captured_ports.txt >> $output_file
  echo "[+] Captured ports saved to output file."
  echo
}

# 2.3.3 Perform Online Lookup for Captured Ports
function lookup_port_online {
  echo "[+] Performing online lookup for captured ports..."
  echo -e "\n2.3.3 Port Online Lookup Results:" >> $output_file
  echo "----------------------------------" >> $output_file

  # Predefined pool of common ports and their descriptions
  declare -A predefined_ports
  predefined_ports=(
    [53]="DNS - Resolves domain names to IP addresses."
    [80]="HTTP - Used for web page traffic."
    [443]="HTTPS - Secure web page traffic."
    [21]="FTP - File Transfer Protocol."
    [22]="SSH - Secure Shell for remote login."
    [25]="SMTP - Simple Mail Transfer Protocol."
    [110]="POP3 - Post Office Protocol."
    [143]="IMAP - Internet Message Access Protocol."
    [3389]="RDP - Remote Desktop Protocol."
  )

  unknown_ports=()  # List to store unknown ports

  while read -r port; do
    if [[ -z "$port" ]]; then
      continue
    fi

    if [[ ${predefined_ports[$port]} ]]; then
      # Found in the predefined list
      echo "- Port $port: ${predefined_ports[$port]}" >> $output_file
    else
      # Unknown port, add to unknown_ports list
      unknown_ports+=("$port")
      echo "- Port $port: Unknown Port" >> $output_file
    fi
  done < /tmp/captured_ports.txt

  # Log unknown ports separately
  if [[ ${#unknown_ports[@]} -gt 0 ]]; then
    echo -e "\nUnknown Ports Found:" >> $output_file
    echo "----------------------------------" >> $output_file
    for port in "${unknown_ports[@]}"; do
      echo "- Port $port: No predefined information available." >> $output_file
    done
  fi

  echo "[+] Port lookup completed. Results saved to output file."
  echo
}


# Main Execution
check_root
display_banner
install_required_tools
setup_output
display_ip_addresses
display_mac_and_vendor
display_router_ips
display_device_names
display_dns_and_dhcp
display_isp
display_connection_type
shodan_check
whois_check
sniff_top_protocols
lookup_port_online

# Display final message
echo -e "\n[+] Script execution complete. Check '$output_file' for the results."
