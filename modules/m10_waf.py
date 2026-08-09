#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AHM Web Scanner - Module 10: WAF (Web Application Firewall) Detection Engine

import httpx

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["server", "cf-ray", "cf-cache-status"],
        "keywords": ["cloudflare", "cf-ray"]
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "keywords": ["aws"]
    },
    "ModSecurity": {
        "headers": ["server"],
        "keywords": ["mod_security", "modsecurity", "NOYB"]
    },
    "Incapsula (Imperva)": {
        "headers": ["x-cdn", "x-iinfo"],
        "keywords": ["incapsula", "visid_incap"]
    },
    "Akamai": {
        "headers": ["server", "x-akamai-transformed"],
        "keywords": ["akamai"]
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "server"],
        "keywords": ["sucuri"]
    },
    "F5 BIG-IP ASM": {
        "headers": ["server", "set-cookie"],
        "keywords": ["bigip", "TS01"]
    }
}

def detect_waf(target_url: str) -> dict:
    """
    Detects if the target web application is protected by a WAF.
    """
    result = {
        "detected": False,
        "waf_name": "None Detected / Direct Connection",
        "details": "No known WAF signature matched."
    }

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
        }
        
        # 1. Normal Request Check
        with httpx.Client(verify=False, timeout=5.0, headers=headers, follow_redirects=True) as client:
            resp = client.get(target_url)
            
            # Check Headers & Cookies
            resp_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            
            for waf, sigs in WAF_SIGNATURES.items():
                for h in sigs["headers"]:
                    if h in resp_headers:
                        for kw in sigs["keywords"]:
                            if kw in resp_headers[h]:
                                result["detected"] = True
                                result["waf_name"] = waf
                                result["details"] = f"Matched HTTP header signature: '{h}: {resp_headers[h]}'"
                                return result

            # 2. Provocative Request (Trigger Potential WAF Rule)
            try:
                waf_test_url = f"{target_url.rstrip('/')}/?test=<script>alert('waf_test')</script>&id=1' OR '1'='1"
                trig_resp = client.get(waf_test_url)
                
                # WAFs often block with 403, 406, or 501
                if trig_resp.status_code in [403, 406, 501]:
                    for waf, sigs in WAF_SIGNATURES.items():
                        for kw in sigs["keywords"]:
                            if kw in trig_resp.text.lower():
                                result["detected"] = True
                                result["waf_name"] = waf
                                result["details"] = f"Active blocking response (HTTP {trig_resp.status_code}) matched signature."
                                return result
                    
                    result["detected"] = True
                    result["waf_name"] = "Generic / Unknown WAF"
                    result["details"] = f"Request blocked with HTTP status code {trig_resp.status_code} on malicious payload injection."
                    return result
            except Exception:
                pass

    except Exception as e:
        result["details"] = f"Connection error during WAF audit: {str(e)}"

    return result
