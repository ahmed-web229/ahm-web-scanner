#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AHM Web Scanner - Module 2: Sensitive Paths & Config Disclosure

import httpx

# Extended List of sensitive paths, their types, risks, indicators, and technical root causes
SENSITIVE_PATHS = [
    {
        "path": "/.env",
        "type": "Environment Config File Leak",
        "risk": "CRITICAL",
        "indicator": "DB_",
        "root_cause": "Environment configuration files containing sensitive credentials were placed in a publicly accessible directory."
    },
    {
        "path": "/.git/HEAD",
        "type": "Git Repository Exposure",
        "risk": "CRITICAL",
        "indicator": "ref: refs/",
        "root_cause": "The .git directory was deployed to the web root without access restriction rules in the web server configuration."
    },
    {
        "path": "/backup.sql",
        "type": "Database Backup File Exposure",
        "risk": "CRITICAL",
        "indicator": "INSERT INTO",
        "root_cause": "Unprotected SQL database backup file placed in the web root allows arbitrary raw data extraction."
    },
    {
        "path": "/wp-config.php.bak",
        "type": "WordPress Backup File Exposure",
        "risk": "HIGH",
        "indicator": "DB_NAME",
        "root_cause": "Text editors or developers created backup files (.bak) in the web root, exposing raw code as plain text."
    },
    {
        "path": "/phpinfo.php",
        "type": "PHP Information Leakage",
        "risk": "MEDIUM",
        "indicator": "PHP Version",
        "root_cause": "Diagnostic files used during development were left on the production server, leaking environment parameters."
    },
    {
        "path": "/robots.txt",
        "type": "Robots Disclosure File",
        "risk": "LOW",
        "indicator": "User-agent:",
        "root_cause": "Standard search engine guidance file; may inadvertently reveal sensitive administrative path locations."
    }
]

def scan_paths(target_url: str) -> list:
    """
    Scans target URL for exposed sensitive paths and gathers preliminary findings.
    Returns candidate vulnerabilities with root causes for verification and reporting.
    """
    candidates = []
    base_url = target_url.rstrip("/")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }

    with httpx.Client(verify=False, timeout=6.0, follow_redirects=False, headers=headers) as client:
        # 1. Detect custom 404 behavior to prevent false positives
        fake_url = f"{base_url}/ahm_non_existent_check_998877.html"
        try:
            fake_resp = client.get(fake_url)
            fake_status = fake_resp.status_code
            fake_len = len(fake_resp.text)
        except Exception:
            fake_status = 404
            fake_len = 0

        # 2. Iterate through sensitive paths
        for item in SENSITIVE_PATHS:
            full_url = f"{base_url}{item['path']}"
            try:
                resp = client.get(full_url)
                
                # Preliminary check: Status 200 and does not match custom 404 response size
                if resp.status_code == 200:
                    if resp.status_code == fake_status and abs(len(resp.text) - fake_len) < 50:
                        continue  # Skip custom 404 responses

                    candidates.append({
                        "url": full_url,
                        "type": item["type"],
                        "risk": item["risk"],
                        "indicator": item["indicator"],
                        "root_cause": item["root_cause"],
                        "response_text": resp.text[:1500],  # Saved snippet for verification engine
                        "status_code": resp.status_code
                    })
            except httpx.RequestError:
                continue

    return candidates
