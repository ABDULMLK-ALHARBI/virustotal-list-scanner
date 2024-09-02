# VirusTotal List Scanner

![Screenshot 2024-09-01 103149](https://github.com/user-attachments/assets/6fc6a921-4479-4406-ba5e-fb7df9aeb528)

The VirusTotal List Scanner is a Python script designed to automate the evaluation of the reputation and security status of various digital resources, including URLs, files, IP addresses, and domains, by utilizing the VirusTotal API. Additionally, we use WHOIS to retrieve domain registration details, further enhancing the tool's ability to provide comprehensive information. This script is particularly valuable for security analysts, IT administrators, and developers who need to efficiently assess the safety of multiple resources in bulk.

## Features

- **Bulk Scanning**: Input a list of resources and retrieve their security and reputation information in a single run.
- **Support for Multiple Resource Types**: Handles URLs, file hashes, IP addresses, and domain names.
- **Automated Report Generation**: Outputs results in a well-organized Excel file.
- **Progress Tracking**: Includes a progress bar to monitor the scanning process.

## Prerequisites

- Python
  
- The following Python libraries:
  
`os`
`argparse`
`requests`
`pandas`
`time`
`datetime`
`tqdm`
`whois`


Install the required libraries :

```bash
All pip install requests will be auto-completed by the script.

```
## Usage
**Windows:** 
- Download ZIP 

```
virustotal-list-scanner-script
```

**Linux:**

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
python vtscan.py 
```
OR
```
python vtscan.py -i input.txt -o output.xlsx
```

## Python libraries 
To list all the Python libraries installed in your environment, you can use the following command:

```
pip list
```
This command will display a list of all installed packages along with their versions.



##
>> Developed by : Abdulmlk Alharbi | Abdulaziz AbuQayyan 
