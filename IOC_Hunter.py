import argparse
import requests
import csv
import json
import time
import base64

VT_API_KEY = '<insert api key here>'
VT_API_URL = "https://www.virustotal.com/api/v3/"

HEADERS = {
    "x-apikey": VT_API_KEY
}

def get_vt_data(ioc: str, ioc_type: str):
    if ioc_type == "url":
        # Encode the URL as required by VirusTotal
        encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        endpoint = f"urls/{encoded_url}"
    elif ioc_type == "ip":
        endpoint = f"ip_addresses/{ioc}"
    else:
        endpoint = f"files/{ioc}"

    url = VT_API_URL + endpoint
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        print(f"[-] {ioc_type.upper()} not found in VirusTotal: {ioc}")
    else:
        print(f"[!] Error querying {ioc}: {response.status_code}")
    return None

def parse_ioc_type(ioc: str):
    ioc = ioc.strip().replace("hxxp://", "http://")
    if "." in ioc and all(part.isdigit() for part in ioc.split('.') if part):
        return "ip"
    elif ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    else:
        return "hash"

def process_iocs(iocs):
    results = []

    for raw_ioc in iocs:
        ioc = raw_ioc.strip().replace("hxxp://", "http://")
        ioc_type = parse_ioc_type(ioc)
        data = get_vt_data(ioc, ioc_type)
        if data:
            attributes = data.get("data", {}).get("attributes", {})
            results.append({
                "ioc": ioc,
                "type": ioc_type,
                "reputation": attributes.get("reputation", "N/A"),
                "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                "harmless_votes": attributes.get("total_votes", {}).get("harmless", "N/A"),
                "malicious_votes": attributes.get("total_votes", {}).get("malicious", "N/A")
            })
        time.sleep(16)  # Respect rate limits for VT public API

    return results

def save_results(results, output_file, output_format):
    if output_format == "csv":
        with open(output_file, "w", newline='') as csvfile:
            fieldnames = results[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
    elif output_format == "json":
        with open(output_file, "w") as jsonfile:
            json.dump(results, jsonfile, indent=4)

def main():
    parser = argparse.ArgumentParser(description="IOC Hunter with VirusTotal Integration")
    parser.add_argument("-f", "--file", help="File containing IOCs (one per line)", required=True)
    parser.add_argument("-o", "--output", help="Output file name", default="results.json")
    parser.add_argument("--format", help="Output format: csv or json", choices=["csv", "json"], default="json")
    args = parser.parse_args()

    try:
        with open(args.file) as f:
            iocs = [line for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}")
        return

    results = process_iocs(iocs)

    if results:
        save_results(results, args.output, args.format)
        print(f"[+] Results saved to {args.output}")
    else:
        print("[-] No valid data returned from VirusTotal.")

if __name__ == "__main__":
    main()