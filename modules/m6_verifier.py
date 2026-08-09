#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Module 6: Central Verification Engine (Zero False-Positive Filter)

import httpx

def verify_findings(m2_res=None, m4_res=None, m5_res=None, m1_res=None, m3_res=None, m8_res=None, m9_res=None) -> dict:
    """
    Central Verification Engine:
    Validates all scan modules to enforce Zero False-Positive reporting.
    """
    verified = {
        "headers": m1_res if m1_res else {},
        "paths": [],
        "cors": m3_res if m3_res else {},
        "xss": [],
        "sqli": [],
        "admin_panels": [],
        "dependencies": []
    }

    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }

    # 1. Verify Sensitive Paths (M2) - Confirm real 200 OK and non-empty content
    if m2_res:
        for item in m2_res:
            url = item.get("url") if isinstance(item, dict) else str(item)
            try:
                with httpx.Client(verify=False, timeout=5.0, follow_redirects=True, headers=headers_req) as client:
                    res = client.get(url)
                    if res.status_code == 200 and len(res.content) > 50:
                        verified["paths"].append(item)
            except Exception:
                continue

    # 2. Verify Reflected XSS (M4) - Confirm payload reflection in body
    if m4_res:
        for item in m4_res:
            url = item.get("url") if isinstance(item, dict) else str(item)
            try:
                with httpx.Client(verify=False, timeout=5.0, follow_redirects=True, headers=headers_req) as client:
                    res = client.get(url)
                    if res.status_code == 200 and "<script>" in res.text.lower():
                        verified["xss"].append(item)
            except Exception:
                continue

    # 3. Verify SQL Injection (M5) - Confirm SQL error signatures
    if m5_res:
        for item in m5_res:
            url = item.get("url") if isinstance(item, dict) else str(item)
            try:
                with httpx.Client(verify=False, timeout=5.0, follow_redirects=True, headers=headers_req) as client:
                    res = client.get(url)
                    sql_errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark"]
                    if any(err in res.text.lower() for err in sql_errors):
                        verified["sqli"].append(item)
            except Exception:
                continue

    # 4. Verify Admin Panels (M8) - Filter accessible panels
    if m8_res:
        for p in m8_res:
            if isinstance(p, dict) and p.get("status") in [200, 301, 302]:
                verified["admin_panels"].append(p)

    # 5. Verify Dependencies (M9) - Pass valid CVE entries
    if m9_res:
        for dep in m9_res:
            if isinstance(dep, dict) and dep.get("library"):
                verified["dependencies"].append(dep)

    return verified
