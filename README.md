# Custom Network Scanner
A network scanner built using Python, Scapy, and other Python-supported libraries. This tool was built for both educational
purposes and to gain a better understanding of network security concepts.

# Features
- **Network Discoveries**: Identifies devices on the network using ARP requests.
- **Port Scanning**: Scans common ports (22, 80, 443) to detect open services.
- **Hostname Resolution**: Resolves IP addresses to human-readable hostnames for easier identification of devices.
- **Output Saving**: Saves scan results into a '.txt' file with a timestamp for later review.
- **Formatted Terminal Output**: Provides a clean, aligned, and professional output.

# Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/b-getz/CustomNetworkScanner.git
   cd CustomNetworkScanner
3. Install required libaries
   Install dependencies from the requirements.txt file provided.
   ```bash
   pip install -r requirements.txt
4. Run the script:
   Use the following command to run the tool, replacing <target IP/range> with the actual target IP or range.
   ```bash
   python CustomNetworkScanner.py -t <target IP/range>
   
# Disclaimer
This tool is intended for **educational purposes** and should **ONLY** be used on owned networks. Unauthorized use of this tool
on networks could result in the violation of local laws and regulations.

# Future Enhancements
1. Allow users to scan custom port ranges.
2. Improve output formatting further with visual elements like color-coding.
3. Implement a web-based interface for scanning and showing results.
