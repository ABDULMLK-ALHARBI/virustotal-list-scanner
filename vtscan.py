import subprocess
import sys
import time
import os
import argparse
import requests
import pandas as pd
from datetime import datetime, timezone
from tqdm import tqdm
import whois

# Function to install missing packages
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# List of required packages
required_packages = [
    'os',
    'argparse',
    'requests',
    'pandas',
    'time',
    'datetime',
    'tqdm',
    'whois'
]

# Try importing each package and install if it's missing
for package in required_packages:
    try:
        __import__(package)
    except ImportError:
        print(f"Package {package} not found. Installing...")
        install(package)

import os
import argparse
import requests
import pandas as pd
import time
from datetime import datetime, timezone
from tqdm import tqdm
import whois

# Example logo to display
logo = r"""
____    ____ .___________.        _______.  ______     ___      .__   __. 
\   \  /   / |           |       /       | /      |   /   \     |  \ |  | 
 \   \/   /  `---|  |----`      |   (----`|  ,----'  /  ^  \    |   \|  | 
  \      /       |  |            \   \    |  |      /  /_\  \   |  . `  | 
   \    /        |  |        .----)   |   |  `----./  _____  \  |  |\   | 
    \__/         |__|        |_______/     \______/__/     \__\ |__| \__| 
"""
# Print the logo without any modifications
print(logo)
print("# Developed by: Abdulmlk Alharbi | Abdulaziz AbuQayyan")
print()

# List of API keys to use
API_KEYS = [
    '187d1128788ecebb23c955d1e5d43f650d055aa8be7f38f208290cde588e6cd2',
    '6fea2b82dafe408313d6091be9219c2eacd4aaeff56a4200d26d2bc499f08048',
    '8cd259d789fdbd34ef2c1708fb99aeea2f154d208d5f1eb2a27d4f9e152ff187',
    #'your_api_key_4',
    #'your_api_key_5',
    #'your_api_key_6',
    #'your_api_key_7',
    #'your_api_key_8',
    #'your_api_key_9',
    #'your_api_key_10'
]
current_key_index = 0

BASE_URL = 'https://www.virustotal.com/api/v3'

def get_vt_report(resource, resource_type):
    global current_key_index
    headers = {
        'x-apikey': API_KEYS[current_key_index]
    }
    url = f"{BASE_URL}/{resource_type}/{resource}"
    response = requests.get(url, headers=headers)

    # Check for rate limit
    if response.status_code == 429:
        # If rate limit is hit, move to the next key
        print(f"API key {current_key_index + 1} rate limit reached, switching to the next key...")
        current_key_index = (current_key_index + 1) % len(API_KEYS)
        time.sleep(0)  # Ensure we wait a bit before trying the next key
        return get_vt_report(resource, resource_type)
    
    return response.json()

def get_whois_info(resource):
    try:
        w = whois.whois(resource)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        domain_name = w.domain_name
        name_servers = w.name_servers

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if isinstance(domain_name, list):
            domain_name = domain_name[0]
        
        if isinstance(name_servers, list):
            name_servers = ', '.join(name_servers)

        if creation_date:
            creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')
        if expiration_date:
            expiration_date = expiration_date.strftime('%Y-%m-%d %H:%M:%S')

        return {
            'whois_domain_name': domain_name if domain_name else 'N/A',
            'whois_registrar': w.registrar if w.registrar else 'N/A',
            'whois_creation_date': creation_date if creation_date else 'N/A',
            'whois_expiration_date': expiration_date if expiration_date else 'N/A',
            'whois_name_servers': name_servers if name_servers else 'N/A'
        }
    except Exception as e:
        return {
            'whois_domain_name': 'N/A',
            'whois_registrar': 'N/A',
            'whois_creation_date': 'N/A',
            'whois_expiration_date': 'N/A',
            'whois_name_servers': 'N/A',
            'whois_error': str(e)
        }

def process_resource(resource, resource_type):
    report = get_vt_report(resource, resource_type)
    attributes = report.get('data', {}).get('attributes', {})
    reputation = attributes.get('reputation', 0)
    
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    malicious = last_analysis_stats.get('malicious', 0)
    suspicious = last_analysis_stats.get('suspicious', 0)
    last_modification_date = attributes.get('last_modification_date', 'N/A')

    if malicious == 0:
        reputation_text = 'unclassified'
    elif malicious > 0:
        reputation_text = 'bad reputation'
    else:
        reputation_text = 'N/A'
    
    
    
    if last_modification_date != 'N/A':
        last_modification_date = datetime.fromtimestamp(last_modification_date, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    
    whois_info = {}
    if resource_type in ['domains', 'ip_addresses']:
        whois_info = get_whois_info(resource)
    
    result = {
        'vt_resource': resource,
        'vt_resource_type': resource_type,
        'vt_reputation': reputation_text,
        'vt_malicious': malicious,
        'vt_suspicious': suspicious,
        'vt_last_modification_date': last_modification_date
    }
    
    result.update(whois_info)
    
    return result

def get_unique_filename(output_file):
    base, extension = os.path.splitext(output_file)
    counter = 1
    while os.path.exists(output_file):
        output_file = f"{base}_{counter}{extension}"
        counter += 1
    return output_file

def main(input_file, output_file):
    output_file = get_unique_filename(output_file)
    
    data = []
    
    with open(input_file, 'r') as file:
        resources = [line.strip() for line in file if line.strip()]
        
        for resource in tqdm(resources, desc="Processing resources", unit="resource"):
            if '@' in resource:
                resource_type = 'urls'
            elif len(resource) in [32, 40, 64]:
                resource_type = 'files'
            elif all(c.isdigit() or c == '.' for c in resource):
                resource_type = 'ip_addresses'
            else:
                resource_type = 'domains'
            
            result = process_resource(resource, resource_type)
            data.append(result)
            time.sleep(0)  # Respect the API rate limit for each key
    
    df = pd.DataFrame(data)
    df.to_excel(output_file, index=False)
    
    print("The scan has been completed.")
    output_file_path = os.path.abspath(output_file)
    print()
    print(f"* The output Excel file is saved at: {output_file_path}")
    print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal List Scanner")
    parser.add_argument('-i', '--input', type=str, default='Add_List_Here.txt', help='Input file with resources to scan')
    parser.add_argument('-o', '--output', type=str, default='vt_results.xlsx', help='Output Excel file')
    parser.add_argument('-v', '--version', action='version', version='VirusTotal Scanner 1.1')
    
    args = parser.parse_args()

    if not args.output.endswith('.xlsx'):
        args.output += '.xlsx'
    
    main(args.input, args.output)
