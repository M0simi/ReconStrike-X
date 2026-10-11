#!/usr/bin/env python3
"""
Tool Name: ReconStrike-X
Description: OSINT Subdomain Enumeration & Service Discovery Automation Tool
Author: M0simi
Version: 1.0.0
License: MIT
"""

import sys
import argparse
import requests
import socket
from concurrent.futures import ThreadPoolExecutor

BANNER = r"""
██████╗ ███████╗ ██████╗ ██████0  ███████╗████████╗██████╗  ██╗  ██╗    ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗ ██╔════╝╚══██╔══╝██╔══██╗ ██║ ██╔╝    ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║ ███████╗   ██║   ██████╔╝ █████╔╝      ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║ ╚════██║   ██║   ██╔══██╗ ██╔═██╗     ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝ ███████║   ██║   ██║  ██║ ██║  ██╗    ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝  ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝
                    [ Advanced OSINT & Recon Automation ]
                          Author: M0simi // M0simi
"""

def print_banner():
    print(BANNER)
    print("-" * 75)

def fetch_subdomains(domain):
    """Fetch subdomains using crt.sh Certificate Transparency logs API"""
    print(f"[*] Querying Certificate Transparency logs for target: {domain}...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                for sub in name_value.split('\n'):
                    sub = sub.strip().lower()
                    # Clean wildcard certificates and check domain match
                    if sub and not sub.startswith('*') and domain in sub:
                        subdomains.add(sub)
        else:
            print(f"[-] Error: Received status code {response.status_code} from crt.sh")
    except Exception as e:
        print(f"[-] Connection error while querying crt.sh: {e}")
        
    return sorted(list(subdomains))

def resolve_subdomain(subdomain):
    """Resolve subdomain IP to check if it's active"""
    try:
        ip = socket.gethostbyname(subdomain)
        return (subdomain, ip, True)
    except socket.gaierror:
        return (subdomain, None, False)

def scan_ports(ip, ports=[80, 443, 8080, 8443]):
    """Basic TCP connect scan on common web ports"""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="ReconStrike-X: Automated OSINT & Subdomain Enumeration Tool by M0simi")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., target.com)")
    parser.add_argument("-r", "--resolve", action="store_true", help="Resolve IPs for discovered subdomains")
    args = parser.parse_args()

    print_banner()
    target = args.domain.strip().lower()
    
    subs = fetch_subdomains(target)
    if not subs:
        print(f"[-] No subdomains found for {target}.")
        sys.exit(0)
        
    print(f"[+] Successfully discovered {len(subs)} unique subdomains.\n")
    
    if args.resolve:
        print("[*] Resolving active hosts and scanning common web ports...")
        print(f"{'SUBDOMAIN':<40} | {'IP ADDRESS':<15} | {'OPEN PORTS'}")
        print("-" * 75)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(resolve_subdomain, subs)
            
        for sub, ip, active in results:
            if active:
                ports = scan_ports(ip)
                ports_str = ", ".join(map(str, ports)) if ports else "None"
                print(f"{sub:<40} | {ip:<15} | {ports_str}")
            else:
                # Optional: print inactive if needed, keeping output clean
                pass
    else:
        print("[*] Discovered Subdomains List:")
        print("-" * 40)
        for sub in subs:
            print(f"  -> {sub}")
            
    print("\n[+] Reconnaissance completed successfully.")
    print("[+] Developed by M0simi | Security Specialist & Red Teamer.")

if __name__ == "__main__":
    main()
