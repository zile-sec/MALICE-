import nmap
import csv
from datetime import datetime
import logging
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_scan_args(category, scan_type):
    if category == 'compliance':
        if scan_type == 'syn':
            return '-sS -sV -p-'
        elif scan_type == 'tcp':
            return '-sT -sV -p-'
        elif scan_type == 'udp':
            return '-sU -sV -p 1-1024'
    elif category == 'discovery':
        if scan_type == 'syn':
            return '-sS -sV -p 1-1024'
        elif scan_type == 'tcp':
            return '-sT -sV -p 1-1024'
        elif scan_type == 'udp':
            return '-sU -sV -p 53,67,68,161'
    elif category == 'audit':
        if scan_type == 'syn':
            return '-sS -sV -p 21,23,25,80,443,3389'
        elif scan_type == 'tcp':
            return '-sT -sV -p 21,23,25,80,443,3389'
        elif scan_type == 'udp':
            return '-sU -sV -p 53,123,161,162'
    return ''

def run_scan(target: str, category: str, scan_type: str, output_file: str):
    """Runs the Nmap scan with the given parameters and saves the results."""
    nm = nmap.PortScanner()
    scan_args = get_scan_args(category, scan_type)
    if not scan_args:
        logging.error("Invalid scan configuration. Exiting.")
        return

    logging.info('Starting Nmap scan on targets: %s with %s %s scan', target, category, scan_type)
    try:
        nm.scan(hosts=target, arguments=scan_args)
    except nmap.PortScannerError as e:
        logging.error('Nmap scan failed: %s', e)
        return
    logging.info('Scan completed successfully')

    # Collect scan data
    scan_data = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    seq = 1
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                row = {
                    # use the requested header names and order (Ip Address with capital I, small p)
                    'S1 Num': seq,
                    'Ip Address': host,
                    'Port': port,
                    'Protocol': proto.upper(),
                    'Service': nm[host][proto][port].get('name', 'N/A'),
                    'Version': nm[host][proto][port].get('version', 'N/A'),
                    'State': nm[host][proto][port]['state'],
                    'Timestamp': timestamp,
                    'volume': 0
                }
                scan_data.append(row)
                seq += 1

    # Define CSV fieldnames in the exact requested order (append 'volume')
    fieldnames = ['S1 Num', 'Ip Address', 'Port', 'Protocol', 'Service', 'Version', 'State', 'Timestamp', 'volume']

    # Write results to CSV
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(scan_data)

    print(f"Scan results saved to {output_file}")
    print(f"Scanned {len(nm.all_hosts())} hosts. {len(scan_data)} open ports found.\n")

def main():
    """Parses command-line arguments and initiates the network scan."""
    parser = argparse.ArgumentParser(
        description="Automated Nmap Scanner for compliance, discovery, or audit purposes.",
        epilog="Example: python networkscan.py 192.168.1.0/24 --category discovery --type syn -o discovery_results.csv"
    )
    parser.add_argument("target", help="Target IP address or network range (e.g., 192.168.1.1 or 192.168.1.0/24).")
    parser.add_argument(
        "--category",
        required=True,
        choices=['compliance', 'discovery', 'audit'],
        help="The category of the scan."
    )
    parser.add_argument(
        "--type",
        required=True,
        choices=['syn', 'tcp', 'udp'],
        help="Type of scan to perform."
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Output CSV file for scan results."
    )
    args = parser.parse_args()

    run_scan(args.target, args.category, args.type, args.output)

if __name__ == "__main__":
    main()