import subprocess
import json
import logging
import argparse
from datetime import datetime
import shutil

# Set up logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s',
                   handlers=[logging.FileHandler('wireshark_analysis.log'),
                             logging.StreamHandler()])

def capture_traffic(interface: str, duration: int, output_file: str):
   """Capture network traffic using tshark."""
   try:
       cmd = [
           'tshark', '-i', interface, '-a', f'duration:{duration}',
           '-w', output_file
       ]
       logging.info(f"Starting capture on {interface} for {duration} seconds...")
       subprocess.run(cmd, check=True)
       logging.info(f"Capture saved to {output_file}")
   except FileNotFoundError:
       logging.error("tshark command not found. Please ensure Wireshark/tshark is installed and in your system's PATH.")
       return False
   except subprocess.CalledProcessError as e:
       logging.error(f"Capture failed: {e}")
       return False
   return True

def analyze_capture(pcap_file: str, output_json: str):
    """Analyze the captured traffic and save results."""
    results = []
    try:
        cmd = [
            'tshark', '-r', pcap_file, '-T', 'fields',
            '-e', 'frame.time',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', '_ws.col.Protocol',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-E', 'header=n',
            '-E', 'separator=,'
        ]
        output = subprocess.check_output(cmd, text=True).strip().split('\n')
        for line in output:
            if not line:  # Skip empty lines
                continue

            fields = line.split(',')
            if len(fields) < 8:
                continue

            timestamp = fields[0]
            src_ip = fields[1]
            dst_ip = fields[2]
            protocol = fields[3].upper()

            # Correctly assign ports based on protocol
            dst_port_str = None
            if 'TCP' in protocol:
                dst_port_str = fields[5]
            elif 'UDP' in protocol:
                dst_port_str = fields[7]

            # Skip entries without a valid destination port
            if not dst_port_str or not dst_port_str.isdigit():
                continue

            entry = {
                'timestamp': timestamp,
                'protocol': protocol,
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'destination_port': int(dst_port_str),
                'action': 'ALLOW'  # Default action since we are just observing
            }
            results.append(entry)
        with open(output_json, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Analysis saved to {output_json}")
    except Exception as e:
        logging.error(f"Analysis failed: {e}")

def main():
   # Check for tshark before starting
   if not shutil.which("tshark"):
       logging.error("tshark command not found. Please ensure Wireshark/tshark is installed and in your system's PATH.")
       return

   parser = argparse.ArgumentParser(description='Automate Wireshark traffic analysis')
   parser.add_argument('interface', help='Network interface to capture from (e.g., eth0)')
   parser.add_argument('--duration', type=int, default=30, help='Capture duration in seconds (default: 30)')
   parser.add_argument('--output_pcap', default='capture.pcap', help='Output pcap file')
   parser.add_argument('--output_json', default='traffic_analysis.json', help='Output JSON file')
   args = parser.parse_args()

   if capture_traffic(args.interface, args.duration, args.output_pcap):
       analyze_capture(args.output_pcap, args.output_json)

if __name__ == '__main__':
   main()