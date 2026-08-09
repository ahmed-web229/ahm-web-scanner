#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Module 9: JS & Technology Dependency Vulnerability Scanner

import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Vulnerability Database for Common Outdated Frontend Libraries
KNOWN_VULNERABILITIES = {
    "jquery": [
        {"version_lt": "1.12.0", "cve": "CVE-2015-9251", "risk": "Medium", "desc": "Reflected XSS in jQuery.getScript()"},
        {"version_lt": "3.5.0", "cve": "CVE-2020-11022", "risk": "Medium", "desc": "Regex in jQuery.htmlPrefilter leads to XSS"}
    ],
    "bootstrap": [
        {"version_lt": "3.4.1", "cve": "CVE-2019-8331", "risk": "Medium", "desc": "XSS in Tooltip/Popover components"},
        {"version_lt": "4.3.1", "cve": "CVE-2019-8331", "risk": "Medium", "desc": "XSS via data-template attributes"}
    ],
    "angular": [
        {"version_lt": "1.8.0", "cve": "CVE-2020-7676", "risk": "High", "desc": "Universal ReDoS & Prototype Pollution"}
    ]
}

def scan_dependencies(target_url: str) -> list:
    """
    Scans the target webpage HTML and scripts to detect library versions and known CVEs.
    """
    findings = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AHM_Web_Scanner/1.0"}

    try:
        response = requests.get(target_url, headers=headers, timeout=10, verify=False)
        html_content = response.text

        # Detect jQuery
        jquery_match = re.search(r'jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)', html_content, re.IGNORECASE)
        if jquery_match:
            version = jquery_match.group(1)
            _check_version("jquery", version, findings)

        # Detect Bootstrap
        bootstrap_match = re.search(r'bootstrap[.-]([0-9]+\.[0-9]+\.[0-9]+)', html_content, re.IGNORECASE)
        if bootstrap_match:
            version = bootstrap_match.group(1)
            _check_version("bootstrap", version, findings)

        # Detect Angular
        angular_match = re.search(r'angular[.-]([0-9]+\.[0-9]+\.[0-9]+)', html_content, re.IGNORECASE)
        if angular_match:
            version = angular_match.group(1)
            _check_version("angular", version, findings)

    except Exception:
        pass

    return findings

def _check_version(lib_name: str, detected_version: str, findings: list):
    """
    Compares detected version against known vulnerability thresholds.
    """
    rules = KNOWN_VULNERABILITIES.get(lib_name, [])
    
    def parse_ver(v_str):
        return tuple(map(int, (v_str.split('.'))))

    try:
        det_v = parse_ver(detected_version)
        for rule in rules:
            rule_v = parse_ver(rule["version_lt"])
            if det_v < rule_v:
                findings.append({
                    "library": lib_name.capitalize(),
                    "version": detected_version,
                    "cve": rule["cve"],
                    "risk": rule["risk"],
                    "description": rule["desc"]
                })
    except ValueError:
        pass
