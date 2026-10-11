# ReconStrike-X 🛡️

> Automated OSINT, Subdomain Enumeration & Service Discovery Tool.
> **Author:** M0simi

## Overview
**ReconStrike-X** is a lightweight, efficient command-line reconnaissance utility built for cybersecurity professionals, penetration testers, and bug bounty hunters. It automates the discovery of subdomains using Certificate Transparency logs (`crt.sh`) and verifies active hosts with multithreaded DNS resolution and port probing.

## Features
* **Passive Reconnaissance:** Query transparency logs safely without direct disruptive traffic against target infrastructure.
* **Multithreaded Resolution:** Quickly resolve IP addresses for large lists of subdomains.
* **Port Probing:** Check common web ports (`80`, `443`, `8080`, `8443`) on active hosts.
* **Cross-Platform:** Works seamlessly on Windows, Linux, and macOS via Python 3.

## Installation
Clone the repository and install dependencies:
```
git clone https://github.com/M0simi/ReconStrike-X.git
cd ReconStrike-X
pip install -r requirements.txt
```

## Usage
Run basic subdomain discovery:
```
python recon_strike.py -d example.com
```
Run discovery with active IP resolution and port scanning:
```
python recon_strike.py -d example.com --resolve
```
