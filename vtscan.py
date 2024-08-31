import os
import argparse

# Check for required libraries
required_libraries = {
    'requests': 'requests',
    'pandas': 'pandas',
    'tqdm': 'tqdm'
}

for lib, package in required_libraries.items():
    try:
        __import__(lib)
    except ImportError:
        print(f"Error: The '{lib}' library is not installed. Please install it using the command: pip install {package}")
        exit(1)

import requests
import pandas as pd
import time
from datetime import datetime, timezone
from tqdm import tqdm  # Import tqdm for the progress bar

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

# استبدل YOUR_VIRUSTOTAL_API_KEY بمفتاح API الخاص بك
API_KEY = '187d1128788ecebb23c955d1e5d43f650d055aa8be7f38f208290cde588e'
BASE_URL = 'https://www.virustotal.com/api/v3'

def get_vt_report(resource, resource_type):
    headers = {
        'x-apikey': API_KEY
    }
    url = f"{BASE_URL}/{resource_type}/{resource}"
    response = requests.get(url, headers=headers)
    return response.json()

def process_resource(resource, resource_type):
    report = get_vt_report(resource, resource_type)
    attributes = report.get('data', {}).get('attributes', {})
    reputation = attributes.get('reputation', 0)

    if reputation == 0:
        reputation_text = 'unclassified'
    elif reputation < 0:
        reputation_text = 'bad reputation'
    else:
        reputation_text = 'N/A'
    
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    malicious = last_analysis_stats.get('malicious', 0)
    suspicious = last_analysis_stats.get('suspicious', 0)
    last_modification_date = attributes.get('last_modification_date', 'N/A')
    
    if last_modification_date != 'N/A':
        last_modification_date = datetime.fromtimestamp(last_modification_date, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    
    return {
        'resource': resource,
        'resource_type': resource_type,
        'reputation': reputation_text,
        'malicious': malicious,
        'suspicious': suspicious,
        'last_modification_date': last_modification_date
    }

def main(input_file, output_file):
    data = []
    
    with open(input_file, 'r') as file:
        resources = [line.strip() for line in file if line.strip()]
        
        for resource in tqdm(resources, desc="Processing resources", unit="resource"):  # Wrap the loop with tqdm
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
            # احترام حدود المعدل الخاص بـ VirusTotal
            time.sleep(15)
    
    df = pd.DataFrame(data)
    df.to_excel(output_file, index=False)
    
    # Print a completion message after all processing is done
    print("The scan has been completed.")
    
    # Print the absolute path of the output file
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

    # Ensure the output file has a .xlsx extension
    if not args.output.endswith('.xlsx'):
        args.output += '.xlsx'
    
    main(args.input, args.output)
