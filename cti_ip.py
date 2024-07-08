import argparse
import requests
import json
import time
import getpass
from colorama import Fore, Style, init
from datetime import datetime
import os
from collections import Counter

init(autoreset=True)

URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
API_KEY_FILE = 'api_keys.txt'

COLORS = {
    'malicious': Fore.RED,
    'clean': Fore.GREEN,
}

def get_headers(api_key):
    return {
        'x-apikey': api_key
    }

def check_ip_virustotal(ip, api_key, fast_scan=True):
    headers = get_headers(api_key)
    response = requests.get(URL + ip, headers=headers)
    try:
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.HTTPError as http_err:
        error_msg = f'{Fore.RED}HTTP error occurred: {http_err}'
        return None, error_msg
    except requests.exceptions.RequestException as err:
        error_msg = f'{Fore.RED}Other error occurred: {err}'
        return None, error_msg
    except json.decoder.JSONDecodeError:
        error_msg = f'{Fore.RED}Error decoding JSON for IP: {ip}'
        return None, error_msg

def analyze_ip_data(ip, data, description_mode='simple'):
    if data is None:
        return f"{Fore.YELLOW}{ip} - Error retrieving data", None

    try:
        attributes = data['data']['attributes']
        country = attributes.get('country', 'Unknown')
        last_analysis_results = attributes['last_analysis_results']

        # Organize results by flags
        organized_results = {
            'malicious': [],
            'clean': [],
        }

        for vendor, result in last_analysis_results.items():
            if 'malicious' in result['result']:
                organized_results['malicious'].append((vendor, result['result']))
            elif 'clean' in result['result']:
                organized_results['clean'].append((vendor, result['result']))

        if description_mode == 'simple':
            response = f"{ip} | "
            if organized_results['malicious']:
                response += f"{Fore.RED}Malicious | {country} | {len(organized_results['malicious'])} vendors\n"
            else:
                response += f"{Fore.CYAN}Clean | {country}\n"
            return response, country

        elif description_mode == 'full':
            response = f"{ip} - Detailed Vendor Analysis:\n"

            if organized_results['malicious']:
                response += f"{Fore.RED}Malicious:\n"
                for vendor, result in organized_results['malicious']:
                    response += f"    - {vendor}: {result}\n"

            if organized_results['clean']:
                response += f"{Fore.CYAN}Clean:\n"
                for vendor, result in organized_results['clean']:
                    response += f"    - {vendor}: {result}\n"

            return response, country

        else:
            return f"{Fore.YELLOW}{ip} - Invalid description mode: {description_mode}", None

    except KeyError as e:
        return f"{Fore.YELLOW}{ip} - Error in response structure: {e}", None

def print_header():
    header_text = """

   ________________            ________
  / ____/_  __/  _/           /  _/ __ \\

 / /     / /  / /             / //     /
/ /___  / / _/ /   /yahya/  _/ // ____/
\____/ /_/ /___/           /___/_/


    """
    print(Fore.CYAN + Style.BRIGHT + header_text)
    print(Fore.WHITE + "CTI-IP Scanner Based on VirusTotal")
    print(Fore.MAGENTA + "==================================================")

    # Print credits
    print_credits()

    # Tool description
    description = """
    CTI-IP Scanner is a tool designed to analyze IP addresses using VirusTotal API.
    It provides detailed analysis of each IP, categorizing them as malicious or clean based on vendor reports.
"""
    print(Fore.MAGENTA + Style.BRIGHT + description)

def print_credits():
    credits = """
    Tool created by Yahya El Ourdighi
    https://www.linkedin.com/in/yahya-el-ourdighi-175028244/
    https://github.com/yahyaelourdighi
    """
    print(Fore.YELLOW + credits)

def save_results(ip_list, api_key, save_option):
    now = datetime.now()
    date_time = now.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"ip_scan_results_{date_time}_{save_option}.txt"

    with open(filename, 'w') as file:
        for ip in ip_list:
            result, error_msg = check_ip_virustotal(ip, api_key)
            if result:
                analysis_result, _ = analyze_ip_data(ip, result, 'full')
                file.write(analysis_result + "\n\n")
            else:
                print(error_msg)

    print(f"{Fore.GREEN}Results saved to {filename}")

def get_api_keys():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, 'r') as file:
            api_keys = file.read().strip().splitlines()
        return api_keys
    return []

def save_api_key(api_key):
    with open(API_KEY_FILE, 'w') as file:
        file.write(api_key)
    print(f"{Fore.GREEN}API key saved successfully.")

def print_dashboard(malicious_count, clean_count, total_count, top_countries):
    now = datetime.now()
    date_time = now.strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{Fore.MAGENTA + Style.BRIGHT}Scan Summary:")
    print(f"{Fore.MAGENTA + Style.BRIGHT}=================")
    print(f"Total Malicious IPs: {Fore.RED + str(malicious_count)}")
    print(f"Total Clean IPs: {Fore.GREEN + str(clean_count)}")
    print(f"Total IPs Scanned: {Fore.CYAN + str(total_count)}")
    print(f"Date of the Scan: {Fore.YELLOW + date_time}")
    print(f"Top 5 Countries:")
    for country, count in top_countries.most_common(5):
        print(f"{country}: {count} IPs")

def main():
    print_header()

    api_keys = get_api_keys()

    if not api_keys:
        print(f"{Fore.MAGENTA}No API keys found in {API_KEY_FILE}. Please add API keys and retry.")
        return

    current_key_index = 0
    api_key = api_keys[current_key_index]

    parser = argparse.ArgumentParser(description='CTI-IP Scanner: Analyze IP addresses using VirusTotal API.')

    parser.add_argument('-d', '--description-mode', choices=['simple', 'full'], default='simple',
                        help='Specify description mode: "simple" for brief analysis, "full" for detailed analysis.')

    args = parser.parse_args()

    input_type = input(Fore.WHITE + Style.BRIGHT + "Do you want to scan a single IP or a list of IPs? (single/list): ").strip().lower()

    if input_type == 'single':
        ip = input(Fore.WHITE + Style.BRIGHT + "Enter the IP address to scan: ").strip()

        result, error_msg = check_ip_virustotal(ip, api_key)

        while result is None and current_key_index < len(api_keys) - 1:
            print(error_msg)
            change_key = input(Fore.YELLOW + "Do you want to use a different API key? (yes/no): ").strip().lower()
            if change_key == 'yes':
                current_key_index += 1
                api_key = api_keys[current_key_index]
                result, error_msg = check_ip_virustotal(ip, api_key)
            else:
                break

        if result:
            analysis_result, _ = analyze_ip_data(ip, result, args.description_mode)
            print(analysis_result)

            output_option = input(Fore.YELLOW + Style.BRIGHT + "Do you want to save the result to a text file? (yes/no): ").strip().lower()
            if output_option == 'yes':
                save_option = input(Fore.MAGENTA + Style.BRIGHT + "Save only malicious IPs, clean IPs, or all results? (malicious/clean/all): ").strip().lower()
                save_results([ip], api_key, save_option)

    elif input_type == 'list':
        ip_list_path = input(Fore.WHITE + Style.BRIGHT + "Enter the path to the file containing IP addresses: ").strip()

        with open(ip_list_path, 'r') as file:
            ip_list = file.read().splitlines()

        malicious_count = 0
        clean_count = 0
        country_counter = Counter()

        for ip in ip_list:
            result, error_msg = check_ip_virustotal(ip, api_key)

            while result is None and current_key_index < len(api_keys) - 1:
                print(error_msg)
                change_key = input(Fore.YELLOW + "Do you want to use a different API key? (yes/no): ").strip().lower()
                if change_key == 'yes':
                    current_key_index += 1
                    api_key = api_keys[current_key_index]
                    result, error_msg = check_ip_virustotal(ip, api_key)
                else:
                    break

            if result:
                analysis_result, country = analyze_ip_data(ip, result, args.description_mode)
                print(analysis_result)
                if analysis_result:
                    if "Malicious" in analysis_result:
                        malicious_count += 1
                    elif "Clean" in analysis_result:
                        clean_count += 1
                    if country:
                        country_counter[country] += 1
                time.sleep(15)

        total_count = len(ip_list)
        print_dashboard(malicious_count, clean_count, total_count, country_counter)

        output_option = input(Fore.WHITE + Style.BRIGHT + "Do you want to save the results to a text file? (yes/no): ").strip().lower()
        if output_option == 'yes':
            save_option = input(Fore.WHITE + Style.BRIGHT + "Save only malicious IPs, clean IPs, or all results? (malicious/clean/all): ").strip().lower()
            save_results(ip_list, api_key, save_option)

    else:
        print(f"{Fore.MAGENTA}Invalid option selected. Exiting.")

if __name__ == '__main__':
    main()
