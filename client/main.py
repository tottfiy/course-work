import subprocess
import json
import re


CORE_SERVER = "http://127.0.0.1:8000"


def run_scan(ipaddress: str) -> str:
    result = subprocess.run(
        ['nmap', '-p-', ipaddress],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return ""

    return result.stdout

def fetch_host() -> dict:
    info = {"hostname": "", "ip_addr": ""}
    
    hostname = subprocess.run(
        ['hostname'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if hostname.returncode != 0:
        print(f"Error: {hostname.stderr}")
        return ""
    else:
        info["hostname"] = hostname
    
    ip_addr = subprocess.run(
        ['ifconfig eth0', 
        '|',
        'grep \'inet \'',
        '|',
        'awk \'{print $2}\''],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if ip_addr.returncode != 0:
        print(f"Error: {ip_addr.stderr}")
        return ""
    else:
        info["ip_addr"] = ip_addr
    
    return info
    

# def construct(nmap_output: str) -> 

# def send(core_ip: str, scan_data: dict):



def main():
    host = fetch_host
    output = run_scan("127.0.0.1")

    if not output or not host:
        return
    print(host, output)


if __name__ == "__main__":
    main()