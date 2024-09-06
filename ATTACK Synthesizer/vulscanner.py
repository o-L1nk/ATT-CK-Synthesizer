import subprocess
import re
import socket
import sys

def run_nmap_vulscan(target):
    command = ['nmap', '-sV', '--script=vulscan/vulscan.nse', target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Check if host is up or down
        if "Host is up" not in result.stdout:
            return "Host is down or unreachable."
        
        return filter_vulnerable_items(result.stdout)
    
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

def filter_vulnerable_items(output):
    lines = output.splitlines()
    filtered_output = []
    open_ports = []

    for line in lines:
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Identify and collect open ports
        if re.match(r"^(\d+)/tcp\s+open", line):
            open_ports.append(line)

        # Identify vulnerable items based on patterns or keywords
        if re.search(r"\[CVE-\d+-\d+\]", line):
            filtered_output.append(line)
        elif line.startswith("Service Info:") or line.startswith("Nmap done:"):
            pass  # Skip these lines
        else:
            # Optionally, include other relevant patterns or keywords to filter
            pass

    if not filtered_output:
        filtered_output.append("No vulnerabilities found.")

    # Include open ports information if available
    if open_ports:
        filtered_output.append("\nOpen Ports:")
        filtered_output.extend(open_ports)
    else:
        filtered_output.append("No open ports found.")

    return "\n".join(filtered_output)

def validate_ip_address(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False

# Function to handle the command-line argument and initiate the scan
def start_scan():
    if len(sys.argv) != 2:
        print("Usage: python3 vulscanner.py <target_ip>")
        return
    
    target_ip = sys.argv[1]
    
    # Validate input
    if not validate_ip_address(target_ip):
        print("Invalid IP address entered. Please enter a valid IP address.")
        return
    
    # Execute nmap scan
    scan_result = run_nmap_vulscan(target_ip)
    
    # Display filtered output or host status
    print(scan_result)

# Example usage:
if __name__ == "__main__":
    start_scan()
