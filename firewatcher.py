import re
import json
import logging
import argparse
import shutil
import tempfile
import os
from datetime import datetime
from typing import Dict, Optional, List

# Set up logging to track script activity and errors
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('log_collection.log'),
                        logging.StreamHandler()
                    ])

def print_program_info():
    """Prints information about the program."""
    print("="*60)
    print("Firewall Log Watcher and Parser")
    print("This script reads firewall logs, parses them, and saves them as JSON.")
    print("Type 'exit' to quit the program.")
    print("="*60)

# Regex pattern for parsing firewall logs (adjust this to match your log format)
# LOG_PATTERN for Windows Firewall logs
# Fields: date time action protocol src-ip dst-ip src-port dst-port ...
# Using \S+ to robustly handle both IPv4 and IPv6 addresses.
LOG_PATTERN = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+\d+\s+(\d+)\s+.*'

def parse_log_entry(entry: str) -> Optional[Dict[str, str]]:
    """Parse a log entry into a dictionary, return None if parsing fails."""
    # First, ignore comments and header lines in the log file
    if entry.startswith('#'):
        return None

    match = re.match(LOG_PATTERN, entry)
    if match:
        # The pattern captures groups in a different order to match Windows logs
        timestamp_str, action, protocol, source_ip, dest_ip, dest_port = match.groups()
        try:
            # Validate timestamp format and convert to ISO 8601 for consistency
            timestamp_obj = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            return {
                'timestamp': timestamp_obj.isoformat(),
                'protocol': protocol.upper(),
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'destination_port': int(dest_port),
                'action': action.upper()
            }
        except ValueError:
            logging.warning(f'Invalid timestamp or port format in log entry: {entry}')
            return None
    else:
        # Ignore blank lines silently
        if entry:
            logging.warning(f'Failed to parse log entry: {entry}')
        return None

def main(log_file_path: str, output_file_path: str) -> None:
    """Read log file, parse entries, and save as JSON."""
    parsed_entries: List[Dict[str, str]] = []    
    
    def process_file(path: str):
        """Helper function to parse a given log file."""
        with open(path, 'r', encoding='utf-8', errors='ignore') as log_file:
            for line in log_file:
                entry = parse_log_entry(line.strip())
                if entry:
                    parsed_entries.append(entry)

    try:
        process_file(log_file_path)
    except FileNotFoundError:
        logging.error(f'Log file not found at: {log_file_path}')
        return
    except PermissionError:
        logging.warning(f'Permission denied for "{log_file_path}". Attempting to read from a temporary copy.')
        temp_path = None
        try:
            # Create a temporary file to copy the log to, which avoids file-locking issues.
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".log", prefix="firewatcher_") as tmp:
                temp_path = tmp.name
            
            shutil.copy2(log_file_path, temp_path)
            logging.info(f'Copied log to temporary file: {temp_path}')
            
            process_file(temp_path)

        except Exception as e:
            logging.error(f'Failed to process temporary copy. Error: {e}')
            return
        finally:
            # Clean up the temporary file
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
                logging.info(f'Removed temporary file: {temp_path}')
    except IOError as e:
        logging.error(f'An I/O error occurred: {str(e)}')
        return

    if parsed_entries:
        with open(output_file_path, 'w') as output_file:
            json.dump(parsed_entries, output_file, indent=4)
        
        logging.info(f'Successfully parsed {len(parsed_entries)} log entries.')
        logging.info(f'Results saved to {output_file_path}')
    else:
        logging.warning("No valid log entries were parsed. The output file will not be created.")

def run_interactive_mode():
    """Runs the script in an interactive mode, prompting the user for input."""
    print_program_info()
    try:
        while True:
            log_file_path = input("Enter the path to the firewall log file (or 'exit' to quit): ").strip()
            if log_file_path.lower() == 'exit':
                print("Exiting program.")
                break

            output_file_path = input("Enter the path for the output JSON file (default: parsed_logs.json): ").strip()
            if not output_file_path:
                output_file_path = 'parsed_logs.json'

            main(log_file_path, output_file_path)
            print("\n" + "="*60 + "\n")
    except (KeyboardInterrupt, EOFError):
        print("\n\nExiting program. Goodbye!")

if __name__ == '__main__':
    run_interactive_mode()