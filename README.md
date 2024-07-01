# CTI-IP Scanner

CTI-IP Scanner is a Python tool designed for analyzing IP addresses using the VirusTotal API. It provides detailed insights into each IP's reputation based on reports from multiple antivirus engines and other security sources.

![CTI-IP Scanner](https://i.ibb.co/j6yGtgy/cti.png)

## Features

- **Single IP or List Scan:** Choose to scan a single IP address interactively or provide a list of IP addresses via a file.
- **Fast and Slow Scan Modes:** Optimize scan speed based on your VirusTotal API capabilities.
- **Detailed Analysis:** View a breakdown of each IP's reputation, categorizing them as malicious or clean.
- **Customizable Output:** Save results to a file, choosing to include only malicious or clean IPs.
- **User-friendly Interface:** Utilizes Colorama for colorful console output and interactive prompts.

## Usage

- **Single IP Scan:** Enter an IP address and receive immediate analysis.
- **List IP Scan:**: Choose the file list of IP addresses you want to scan.
  
  ```bash
  python cti_ip.py --help
  ``` 
You will be prompted to enter the IP address you wish to scan.

## List IP Scan
To scan a list of IP addresses from a file (ip_list.txt), use the following command:
  ```bash
  Do you want to scan a single IP or a list of IPs? (single/list): list
  ``` 
## Notes
- **Example:** Provide specific examples for both single IP and list IP scans to guide users effectively.
- **Customization:** Highlight the --help flag usage to encourage users to explore additional features and options.
## Requirements
Python 3.x
requests library for HTTP requests
colorama library for colored terminal output
  ```bash
  pip install -r requirements.txt
  ```

## Installation
- **Clone the repository:**

```bash
git clone https://github.com/YahyaElOurdighi/CTI-IP-Scanner.git
cd CTI-IP-Scanner
```

- **Install dependencies:**

```bash
pip install -r requirements.txt
```
Ensure you have Python 3.x and pip installed on your system.

## API Keys and Configuration
Obtain a **VirusTotal API** key from VirusTotal.
Store your API keys in a file named **api_keys.txt**, each key on a new line.

## Screenshots

![CTI-IP Scanner](https://gcdnb.pbrd.co/images/ElI24ydzl0vg.png?o=1)
