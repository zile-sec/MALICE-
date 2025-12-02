import pandas as pd
import argparse
import logging
from typing import Dict

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_scan_lookup(scan_df: pd.DataFrame) -> dict:
    """Creates a lookup dictionary from the network scan data for quick access."""
    lookup = {}
    for _, row in scan_df.iterrows():
        key = (row['IP Address'], row['Port'], row['Protocol'])
        lookup[key] = row['State']
    return lookup

def apply_labeling_heuristic(log_entry: pd.Series, scan_lookup: Dict) -> int:
    """
    Applies a stateful heuristic to label data as an attack (1) or benign (0).
    
    This heuristic uses pre-computed temporal features to identify suspicious patterns.
    """
    # --- Define Critical Ports (commonly targeted in attacks) ---
    CRITICAL_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900, 8080}

    # --- Rule 1: High-confidence attack patterns (Port/Denial scans) ---
    # High frequency of denials or connections to many unique ports from one source.
    if log_entry['deny_count_in_window'] > 20 or log_entry['unique_ports_in_window'] > 20:
        return 1

    # --- Rule 2: Allowed traffic is considered benign ---
    if log_entry['action'] == 'ALLOW':
        return 0

    # --- Rule 3: Analyze DENY actions with more context ---
    key = (log_entry['destination_ip'], log_entry['destination_port'], log_entry['protocol'])
    port_state = scan_lookup.get(key, 'unknown')

    if log_entry['action'] == 'DENY':
        # Deny to a known-closed port is a strong indicator of a scan.
        if port_state == 'closed':
            return 1
        
        # Deny to a critical port is suspicious.
        if log_entry['destination_port'] in CRITICAL_PORTS:
            return 1
        
        # Deny to a port that the firewall is actively filtering is expected behavior.
        # This is less likely to be a targeted attack and more likely noise.
        if port_state == 'filtered':
            return 0

        # If we have some denials but not enough to trigger the high-confidence rule,
        # label it as suspicious but let the model learn the pattern.
        if log_entry['deny_count_in_window'] > 5:
            return 1

    # --- Rule 4: Default to benign for anything else ---
    # This includes isolated DENY events to non-critical, non-closed ports.
    return 0

def main(scan_file: str, log_file: str, output_file: str):
    """
    Loads network scan and firewall log data, combines them, applies a labeling
    heuristic, and saves the result to a CSV file for model training.
    """
    logging.info("Loading network scan data from %s", scan_file)
    try:
        scan_df = pd.read_csv(scan_file)
    except FileNotFoundError:
        logging.error("Network scan file not found: %s", scan_file)
        return

    logging.info("Loading firewall log data from %s", log_file)
    try:
        log_df = pd.read_json(log_file)
    except FileNotFoundError:
        logging.error("Firewall log file not found: %s", log_file)
        return
    
    if log_df.empty:
        logging.warning("Firewall log file is empty. No dataset will be generated.")
        return
        
    # --- Temporal Feature Engineering ---
    # Convert timestamp to datetime objects for time-based analysis.
    log_df['timestamp'] = pd.to_datetime(log_df['timestamp'])
    log_df = log_df.sort_values('timestamp').set_index('timestamp')

    logging.info("Calculating temporal features for stateful analysis...")
    # For each source IP, count denied connections in a 5-minute rolling window.
    deny_mask = log_df['action'] == 'DENY'
    deny_counts = log_df[deny_mask].groupby('source_ip').rolling('5min').size().rename('deny_count_in_window')
    
    # For each source IP, count unique destination ports targeted in a 5-minute window.
    unique_ports = log_df.groupby('source_ip')['destination_port'].rolling('5min').apply(lambda x: x.nunique()).rename('unique_ports_in_window')

    # Merge these new temporal features back into the main log dataframe.
    log_df = log_df.reset_index().merge(deny_counts.reset_index(), on=['source_ip', 'timestamp'], how='left')
    log_df = log_df.merge(unique_ports.reset_index(), on=['source_ip', 'timestamp'], how='left')
    
    # Fill NaN values that result from the rolling window calculation.
    log_df['deny_count_in_window'].fillna(0, inplace=True)
    log_df['unique_ports_in_window'].fillna(0, inplace=True)

    # Create the fast lookup table from the scan data
    scan_lookup = create_scan_lookup(scan_df)

    # Enrich log data with scan context and apply labels
    logging.info("Enriching data and applying labeling heuristics...")
    log_df['port_state'] = log_df.apply(lambda row: scan_lookup.get((row['destination_ip'], row['destination_port'], row['protocol']), 'unknown'), axis=1)
    log_df['is_attack'] = log_df.apply(apply_labeling_heuristic, axis=1, scan_lookup=scan_lookup)

    # --- Final Feature Selection and Engineering for the Model ---
    # Convert categorical columns into a numerical format using one-hot encoding
    features_df = pd.get_dummies(log_df[['protocol', 'action', 'port_state']], prefix=['proto', 'action', 'state'], dtype=int)
    
    # Select the numerical features we want to feed into the model.
    numerical_features = log_df[['destination_port', 'deny_count_in_window', 'unique_ports_in_window']]

    # Combine the numerical features with the target label
    final_df = pd.concat([features_df, numerical_features, log_df['is_attack']], axis=1)

    # Drop rows with any missing values that might have been created
    final_df.dropna(inplace=True)

    logging.info("Saving prepared dataset to %s", output_file)
    final_df.to_csv(output_file, index=False)
    logging.info("Dataset preparation complete. Shape: %s", final_df.shape)
    logging.info("Attack distribution:\n%s", final_df['is_attack'].value_counts(normalize=True))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Prepare a combined dataset for threat detection.')
    parser.add_argument('scan_file', help='Path to the network scan CSV file.')
    parser.add_argument('log_file', help='Path to the parsed firewall log JSON file.')
    parser.add_argument('output_file', help='Path for the final output CSV dataset.')
    args = parser.parse_args()

    main(args.scan_file, args.log_file, args.output_file)