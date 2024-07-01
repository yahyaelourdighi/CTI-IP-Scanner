# CTI-IP Scanner

CTI-IP Scanner is a Python tool designed for analyzing IP addresses using the VirusTotal API. It provides detailed insights into each IP's reputation based on reports from multiple antivirus engines and other security sources.

![CTI-IP Scanner](https://placehold.it/700x300)

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
