#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated"
]

def scan_sqli(target_url: str) -> list:
    findings = []
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    with httpx.Client(verify=False, timeout=30.0, follow_redirects=True, headers=headers_req) as client:
        for param_name in params.keys():
            test_params = params.copy()
            test_params[param_name] = "1'"
            
            encoded_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, encoded_query, parsed.fragment
            ))

            try:
                resp = client.get(test_url)
                body_lower = resp.text.lower()

                for err in SQL_ERRORS:
                    if err in body_lower:
                        findings.append({
                            "parameter": param_name,
                            "test_url": test_url,
                            "type": "Error-Based SQL Injection",
                            "risk": "CRITICAL",
                            "root_cause": f"Parameter '{param_name}' triggered a database error ('{err}'). User input is improperly concatenated into SQL queries.",
                            "elapsed_time": 3.0
                        })
                        break
            except Exception as e:
                print(f"[!] M5 Error on {param_name}: {e}")

    return findings
