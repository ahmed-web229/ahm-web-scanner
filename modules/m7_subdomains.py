#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AHM Web Scanner - Module 7: Subdomain Discovery Engine

import httpx
from urllib.parse import urlparse

def discover_subdomains(target_url: str) -> list:
    subdomains = set()
    
    parsed = urlparse(target_url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    domain = domain.split(':')[0]
    
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        root_domain = ".".join(domain_parts[-2:])
    else:
        root_domain = domain

    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Source 1: CRT.sh
    crt_url = f"https://crt.sh/?q=%.{root_domain}&output=json"
    try:
        with httpx.Client(verify=False, timeout=30.0, headers=headers_req, follow_redirects=True) as client:
            resp = client.get(crt_url)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(root_domain) and not sub.startswith('*'):
                            subdomains.add(sub)
    except Exception as e:
        print(f"[!] Subdomain Discovery Error: {e}")

    # Source 2: Hackertarget Backup API
    if not subdomains:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
        try:
            with httpx.Client(verify=False, timeout=20.0, headers=headers_req) as client:
                resp = client.get(ht_url)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    lines = resp.text.splitlines()
                    for line in lines:
                        parts = line.split(',')
                        if len(parts) >= 1:
                            sub = parts[0].strip().lower()
                            if sub.endswith(root_domain):
                                subdomains.add(sub)
        except Exception:
            pass

    return sorted(list(subdomains))
