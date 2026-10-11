#!/usr/bin/env python3
"""
Tool Name: ReconStrike-X
Description: OSINT Subdomain Enumeration & Service Discovery Automation Tool
Author: M0simi
Version: 1.2.0
License: MIT
"""

import sys
import argparse
import requests
import socket
from concurrent.futures import ThreadPoolExecutor

BANNER = r"""
██████╗ ███████╗ ██████╗ ██████  ███████╗████████╗██████╗  ██╗  ██╗    ██╗  ██╗
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
    """Fetch subdomains using crt.sh and fallback to HackerTarget API, then filter out the root domain itself"""
    print(f"[*] Querying Certificate Transparency logs for target: {domain}...")
    raw_subdomains = set()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    # Method 1: Try crt.sh
    url_crt = f"https://crt.sh/?q=%25.{domain}&output=json"
    success = False
    
    for attempt in range(2):
        try:
            response = requests.get(url_crt, headers=headers, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        if sub and not sub.startswith('*') and domain in sub:
                            raw_subdomains.add(sub)
                success = True
                break
            else:
                print(f"[-] crt.sh returned status code {response.status_code} (Attempt {attempt+1})")
        except Exception as e:
            print(f"[-] crt.sh connection warning (Attempt {attempt+1}): {e}")
            
    # Method 2: Fallback to HackerTarget API if crt.sh fails or returns nothing
    if not success or not raw_subdomains:
        print(f"[*] Switching to fallback API (HackerTarget) for {domain}...")
        url_ht = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            res = requests.get(url_ht, headers=headers, timeout=15)
            if res.status_code == 200 and "API count exceeded" not in res.text:
                for line in res.text.splitlines():
                    parts = line.split(',')
                    if parts and len(parts) > 0:
                        sub = parts[0].strip().lower()
                        if sub and domain in sub and not sub.startswith('*'):
                            raw_subdomains.add(sub)
        except Exception as e:
            print(f"[-] Fallback API error: {e}")

    # SMART FILTER: Exclude the exact root domain itself so only true subdomains remain
    subdomains = {sub for sub in raw_subdomains if sub != domain}

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
            s.settimeout(0.8)
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
        print(f"[-] No true subdomains found for {target} (or target has no active subdomains recorded).")
        sys.exit(0)
        
    print(f"[+] Successfully discovered {len(subs)} unique subdomains.\n")
    
    if args.resolve:
        print("[*] Resolving active hosts and scanning common web ports...")
        print(f"{'SUBDOMAIN':<40} | {'IP ADDRESS':<15} | {'OPEN PORTS'}")
        print("-" * 75)
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            results = executor.map(resolve_subdomain, subs)
            
        for sub, ip, active in results:
            if active:
                ports = scan_ports(ip)
                ports_str = ", ".join(map(str, ports)) if ports else "None"
                print(f"{sub:<40} | {ip:<15} | {ports_str}")
    else:
        print("[*] Discovered Subdomains List:")
        print("-" * 40)
        for sub in subs:
            print(f"  -> {sub}")
            
    print("\n[+] Reconnaissance completed successfully.")
    print("[+] Developed by M0simi | Security Specialist & Red Teamer.")

if __name__ == "__main__":
    main()
