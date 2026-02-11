import pandas as pd
import os
import re
import requests
import time
import glob
from datetime import datetime
import warnings

# Suppress openpyxl warnings
warnings.filterwarnings('ignore', category=UserWarning, module='openpyxl')

def get_abuseipdb_details(ip, api_key):
    """
    Fetches details for a single IP from AbuseIPDB API.
    """
    if not ip or pd.isna(ip) or str(ip).lower() == "nan":
        return "NA", "NA", "NA", "NA", "NA", "NA"
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': ''
    }
    
    try:
        # First attempt with SSL verification
        response = requests.get(url, headers=headers, params=params, timeout=15)
    except requests.exceptions.SSLError:
        # Fallback for systems with certificate issues
        response = requests.get(url, headers=headers, params=params, timeout=15, verify=False)
    except Exception as e:
        print(f"Error fetching details for {ip}: {e}")
        return "Error", "Error", "Error", "Error", "Error", "Error"

    if response.status_code == 200:
        data = response.json()['data']
        city = data.get('city', 'Unknown')
        state = data.get('regionName') or data.get('region', 'Unknown')
        country = data.get('countryName') or data.get('countryCode', 'Unknown')
        isp = data.get('isp', 'Unknown')
        domain = data.get('domain', 'Unknown')
        isp_full = f"{isp} ({domain})" if domain and domain != 'Unknown' else str(isp)
        usage = data.get('usageType') or "Unknown"
        reputation = f"{data.get('abuseConfidenceScore', 0)}%"
        return city, state, country, isp_full, usage, reputation
    elif response.status_code == 429:
        print(f"Rate limit hit! Waiting 60 seconds...")
        time.sleep(60)
        return get_abuseipdb_details(ip, api_key) # Retry once
    else:
        print(f"API Error {response.status_code} for {ip}")
        return "Error", "Error", "Error", "Error", "Error", "Error"

def extract_ips_from_text(content):
    """
    Extracts IPv4 addresses from a string using regex.
    """
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return list(set(re.findall(ip_pattern, content)))

def get_ips_from_file(file_path):
    """
    Reads a file and extracts unique IP addresses.
    Supports .csv, .xls, .xlsx, and .txt.
    """
    ext = os.path.splitext(file_path)[1].lower()
    ips = set()

    try:
        if ext in ['.xlsx', '.xls', '.csv']:
            if ext == '.csv':
                df = pd.read_csv(file_path)
            else:
                df = pd.read_excel(file_path)
            
            # Look for columns that might contain IPs
            ip_cols = [col for col in df.columns if 'ip' in str(col).lower()]
            
            if ip_cols:
                for col in ip_cols:
                    ips.update(df[col].dropna().astype(str).tolist())
            else:
                # If no IP column found, search all string columns using regex
                print(f"  No explicit IP column found in {os.path.basename(file_path)}. Searching all columns...")
                for col in df.columns:
                    for val in df[col].dropna().astype(str):
                        found = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', val)
                        ips.update(found)
        
        elif ext == '.txt':
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                ips.update(extract_ips_from_text(content))
        
    except Exception as e:
        print(f"  Error reading {file_path}: {e}")
    
    # Filter out invalid IPs (regex is broad, e.g. 999.999.999.999)
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        base_valid = len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        # Exclude common private/local IPs if needed? User didn't specify.
        if base_valid:
            valid_ips.append(ip)
            
    return sorted(list(set(valid_ips)))

def process_bulk_lookup():
    print("=== AbuseIPDB Bulk Lookup Tool ===")
    folder_path = input("Enter the path to the folder containing input files: ").strip()
    api_key = input("Enter your AbuseIPDB API Key: ").strip()

    if not os.path.exists(folder_path):
        print(f"Error: Path '{folder_path}' does not exist.")
        return

    # Find all supported files
    extensions = ['*.csv', '*.xls', '*.xlsx', '*.txt']
    files_to_process = []
    for ext in extensions:
        files_to_process.extend(glob.glob(os.path.join(folder_path, ext)))

    if not files_to_process:
        print("No supported files (.csv, .xls, .xlsx, .txt) found in the specified directory.")
        return

    print(f"\nFound {len(files_to_process)} files to process.")

    for file_path in files_to_process:
        filename = os.path.basename(file_path)
        print(f"\nProcessing: {filename}")
        
        ips = get_ips_from_file(file_path)
        if not ips:
            print(f"  No valid IP addresses found in {filename}.")
            continue
        
        print(f"  Found {len(ips)} unique IPs. Starting AbuseIPDB lookup...")
        
        results = []
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for ip in ips:
            print(f"    Checking {ip}...")
            city, state, country, isp, usage, reputation = get_abuseipdb_details(ip, api_key)
            results.append({
                'Report Generated At': gen_time,
                'Source File': filename,
                'IP Address': ip,
                'City': city,
                'State/City': state, # User requested "State/City"
                'Country': country,
                'Service provider name': isp, # User requested "Service provide name"
                'Type of usage': usage,
                'Reputation': reputation
            })
            time.sleep(0.5) # Modest sleep to avoid aggressive hitting
        
        # Guard against empty results
        if not results:
            continue

        # Generate output file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_name = f"Report_{os.path.splitext(filename)[0]}_{timestamp}.xlsx"
        output_path = os.path.join(folder_path, output_name)
        
        try:
            df_out = pd.DataFrame(results)
            df_out.to_excel(output_path, index=False)
            print(f"  Success! Individual report generated: {output_name}")
        except Exception as e:
            print(f"  Error saving report for {filename}: {e}")

    print("\nBulk lookup completed.")
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    try:
        process_bulk_lookup()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nAn unhandled error occurred: {e}")
