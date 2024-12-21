# Brandon Getz - 10/09/2024 - Initial Program Creation
# Brandon Getz - 12/21/2024 - Program Enhancments (port scanning, saves to .txt, etc.)

import scapy.all as scapy
import argparse
import datetime
import socket

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
        ip_address = element[1].psrc
        mac_address = element[1].hwsrc
        open_ports = scan_ports(ip_address)  # Scan ports on the device
        client = {"ip": ip_address, "mac": mac_address, "ports": open_ports}
        result.append(client)

    return result

# Function to show the scan results to the user
def show_result(result):
    print("-------------------------")
    print("IP Address\t\tMAC Address\t\tOpen Ports")
    print("-------------------------")
    for client in result:
        ports = ", ".join(map(str, client["ports"])) if client["ports"] else "None"
        print(f"{client['ip']}\t\t{client['mac']}\t\t{ports}")


# Function to save results of scan to a .txt file
def save_result(result):
    # Get the current date and time
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Create a file name using the timestamp
    file_name = f"scan_results_{timestamp}.txt"
    
    # Save the results to the file
    with open(file_name, "w") as file:
        file.write("-------------------------\n")
        file.write("IP Address\t\tMAC Address\t\tOpen Ports\n")
        file.write("-------------------------\n")
        for client in result:
            ports = ", ".join(map(str, client["ports"])) if client["ports"] else "None"
            file.write(f"{client['ip']}\t\t{client['mac']}\t\t{ports}\n")
    
    print(f"[+] Results saved to {file_name}")

# Function to scan common ports on a given IP
def scan_ports(ip, ports=[22, 80, 443]):  # Default to common ports
    open_ports = []
    for port in ports:
        try:
            # Create a socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1-second timeout
            
            # Attempt to connect to the port
            result = sock.connect_ex((ip, port))
            if result == 0:  # Port is open
                open_ports.append(port)
            
            sock.close()
        except:
            continue
    return open_ports

# Main script logic
options = get_args()
scan_result = scan(options.target)
show_result(scan_result)
save_result(scan_result)