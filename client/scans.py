import subprocess
import re
import xml.etree.ElementTree as ET
from typing import List, Dict

def run_nmap(ipaddress: str) -> List[Dict]:
    result = subprocess.run(
        ['nmap', '-p-', '-oX', '-', ipaddress],  # XML to stdout
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return []

    return result.stdout

def fetch_host() -> dict:
    info = {"hostname": "", "ip_addr": ""}

    # Get hostname
    hostname = subprocess.run(
        ['hostname'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if hostname.returncode != 0:
        print(f"Error: {hostname.stderr}")
        return {}

    info["hostname"] = hostname.stdout.strip()

    # Get IPv4 address of eth0
    ip_result = subprocess.run(
        ['ifconfig', 
        'eth0'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if ip_result.returncode != 0:
        print(f"Error: {ip_result.stderr}")
        return {}

    # Extract IP using regex
    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ip_result.stdout)
    if match:
        info["ip_addr"] = match.group(1)

    return info

def run_trivy():
    pass

def run_semgrep():
    pass

def run_lynis():
    pass
