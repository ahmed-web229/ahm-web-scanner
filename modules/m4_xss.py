#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SAFE_CANARY = "ahmtestxss123"

def scan_reflected_xss(target_url: str) -> list:
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
            test_params[param_name] = SAFE_CANARY
            
            encoded_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, encoded_query, parsed.fragment
            ))

            try:
                resp = client.get(test_url)
                if SAFE_CANARY in resp.text:
                    findings.append({
                        "parameter": param_name,
                        "test_url": test_url,
                        "risk": "HIGH",
                        "type": "Reflected Parameter Unescaped",
                        "root_cause": f"Parameter '{param_name}' reflects input directly into the HTTP body without HTML encoding.",
                        "evidence": SAFE_CANARY
                    })
            except Exception as e:
                print(f"[!] M4 Error on {param_name}: {e}")

    return findings
