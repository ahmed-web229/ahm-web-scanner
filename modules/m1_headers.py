#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import httpx

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {"risk": "HIGH", "root_cause": "Missing HSTS allows MITM and downgrade attacks."},
    "X-Frame-Options": {"risk": "MEDIUM", "root_cause": "Missing X-Frame-Options enables Clickjacking."},
    "X-Content-Type-Options": {"risk": "LOW", "root_cause": "Missing nosniff header allows MIME-sniffing."},
    "Content-Security-Policy": {"risk": "HIGH", "root_cause": "Missing CSP increases exposure to XSS and data injection."}
}

def analyze_headers(target_url: str) -> dict:
    results = {
        "server": "Unknown / Hidden",
        "technology": "Not Disclosed",
        "missing_headers": [],
        "present_headers": {},
        "error": None
    }
    
    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }

    # Generate trial URLs (HTTPS first, then HTTP)
    base_target = target_url.replace("http://", "").replace("https://", "")
    urls_to_try = [f"https://{base_target}", f"http://{base_target}"]

    response = None
    last_error = "Connection Timed Out"

    for url in urls_to_try:
        try:
            with httpx.Client(verify=False, timeout=8.0, follow_redirects=True, headers=headers_req) as client:
                res = client.get(url)
                if res.status_code < 500:
                    response = res
                    break
        except Exception as e:
            last_error = str(e)
            continue

    if not response:
        results["error"] = last_error
        return results

    # Extract Data
    results["server"] = response.headers.get("Server", "Generic / Protected")
    results["technology"] = response.headers.get("X-Powered-By", "Not Disclosed")
    
    for h_name, h_val in response.headers.items():
        results["present_headers"][h_name] = h_val

    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    for header, details in REQUIRED_HEADERS.items():
        if header.lower() not in headers_lower:
            results["missing_headers"].append({
                "header": header,
                "risk": details["risk"],
                "root_cause": details["root_cause"]
            })

    return results
