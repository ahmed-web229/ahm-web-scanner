#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AHM Web Scanner - Module 3: Dangerous HTTP Methods & CORS Audit

import httpx

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]

def audit_methods_and_cors(target_url: str) -> dict:
    """
    Audits enabled HTTP methods and CORS misconfigurations on the target URL.
    Returns detected risks with technical root causes.
    """
    results = {
        "allowed_methods": [],
        "dangerous_methods_found": [],
        "cors_issues": [],
        "error": None
    }

    try:
        with httpx.Client(verify=False, timeout=8.0, follow_redirects=True) as client:
            # 1. Test HTTP OPTIONS Method
            options_resp = client.options(target_url)
            allow_header = options_resp.headers.get("Allow", "")
            
            if allow_header:
                results["allowed_methods"] = [m.strip() for m in allow_header.split(",")]
            
            # Active check for dangerous methods
            for method in DANGEROUS_METHODS:
                try:
                    res = client.request(method, target_url)
                    if res.status_code in [200, 201, 204] or (method == "TRACE" and "TRACE /" in res.text):
                        results["dangerous_methods_found"].append({
                            "method": method,
                            "status_code": res.status_code,
                            "risk": "HIGH" if method in ["PUT", "DELETE", "TRACE"] else "MEDIUM",
                            "root_cause": f"The HTTP {method} method is enabled on the server without strict authentication, allowing unauthorized state modification or HTTP request tracing."
                        })
                except httpx.RequestError:
                    continue

            # 2. Test CORS Misconfigurations
            origin_test_headers = {"Origin": "https://evil-attacker.com"}
            cors_resp = client.get(target_url, headers=origin_test_headers)

            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*":
                results["cors_issues"].append({
                    "issue": "Wildcard Access-Control-Allow-Origin",
                    "risk": "MEDIUM",
                    "root_cause": "The Access-Control-Allow-Origin header is set to wildcard (*), allowing any external site to read public response data."
                })
            elif acao == "https://evil-attacker.com":
                risk_level = "CRITICAL" if acac == "true" else "HIGH"
                results["cors_issues"].append({
                    "issue": "Arbitrary Origin Reflection with Credentials" if acac == "true" else "Arbitrary Origin Reflection",
                    "risk": risk_level,
                    "root_cause": f"Server reflects arbitrary Origin headers ('https://evil-attacker.com') with Allow-Credentials set to '{acac}', enabling attackers to breach cross-origin privacy and extract authenticated session data."
                })

    except httpx.RequestError as err:
        results["error"] = f"Connection failed: {str(err)}"

    return results
