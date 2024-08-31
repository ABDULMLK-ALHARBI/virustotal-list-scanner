# VirusTotal List Scanner

The VirusTotal List Scanner is a Python-based script designed to automate the process of checking the reputation and security status of various digital resources, such as URLs, files, IP addresses, and domains, by leveraging the VirusTotal API. This tool is particularly useful for security analysts, IT administrators, and developers who need to quickly assess the safety of multiple resources in bulk.

## Features

- **Bulk Scanning**: Input a list of resources and retrieve their security and reputation information in a single run.
- **Support for Multiple Resource Types**: Handles URLs, file hashes, IP addresses, and domain names.
- **Automated Report Generation**: Outputs results in a well-organized Excel file.
- **Progress Tracking**: Includes a progress bar to monitor the scanning process.
- **Rate Limiting Compliance**: Automatically adheres to VirusTotal's API rate limits.

## Prerequisites

- Python
  
- The following Python libraries:
  - `requests`
  - `pandas`
  - `tqdm`
  - `openpyxl`

Install the required libraries using:

```bash
pip install requests pandas tqdm openpyxl
```
## Usage
For Windows : Download .zip 

**Clone the Repository**
```
git clone https://github.com/ABDULMLK-ALHARBI/virustotal-list-scanner.git
```
```
cd virustotal-list-scanner
```


**Set Up Your Environment**

- Replace the placeholder API key in script.py with your actual VirusTotal API key:
```
API_KEY = 'add_your_actual_api_key_here'
```

- Add a list of resources to the file.  

```
Add_List_Here.TXT 
```

**Run the Script**
```
python script.py 
```
OR
```
python script.py -i input.txt -o output.xlsx
```

## Python libraries 
To list all the Python libraries installed in your environment, you can use the following command:

```
pip list
```
This command will display a list of all installed packages along with their versions.


