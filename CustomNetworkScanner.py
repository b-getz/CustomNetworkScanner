# Brandon Getz - 10/09/2024

import scapy.all as scapy
import argparse

# Function to parse command-line arguments
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Addresses')
    options = parser.parse_args()

    # Check for errors, such as if the user does not enter specific target IP Address
    if not options.target:
        parser.error("[-] Please enter a specific IP Address or Addresses...use --help for more information")
    
    return options  # Ensure options are returned

# Function to perform the network scan
def scan(ip):
    # Create ARP request
    arp_req = scapy.ARP(pdst=ip)

    # Create Ethernet frame to broadcast ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine ARP request and Ethernet frame
    arp_broadcast = broadcast / arp_req
    
    # Send the packet and capture responses
    answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]

    # Store results in a list
    result = []
    for element in answered_list:
        client = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        result.append(client)

    return result  # Moved outside the loop

# Function to show the scan results to the user
def show_result(result):
    print("-------------------------")
    print("IP Address\t\tMAC Address")
    print("-------------------------")
    for client in result:
        print(f"{client['ip']}\t\t{client['mac']}")

# Main script logic
options = get_args()
scan_result = scan(options.target)
show_result(scan_result)