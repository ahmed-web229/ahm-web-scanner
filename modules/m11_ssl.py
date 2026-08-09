#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AHM Web Scanner - Module 11: SSL/TLS Certificate Inspector

import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

def inspect_ssl(target_url: str) -> dict:
    """
    Inspects SSL/TLS certificate details and expiration date for HTTPS targets.
    """
    result = {
        "is_https": False,
        "valid": False,
        "issuer": "N/A",
        "days_left": 0,
        "expiry_date": "N/A",
        "details": "Target uses unencrypted HTTP protocol."
    }

    try:
        parsed = urlparse(target_url)
        hostname = parsed.netloc.split(':')[0] if parsed.netloc else parsed.path.split('/')[0]

        # Try connecting over HTTPS port 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                result["is_https"] = True
                result["valid"] = True
                
                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                result["issuer"] = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown Issuer'))
                
                # Extract Dates
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    exp_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    result["expiry_date"] = exp_date.strftime('%Y-%m-%d')
                    
                    days_remaining = (exp_date - datetime.utcnow()).days
                    result["days_left"] = days_remaining
                    
                    if days_remaining < 0:
                        result["valid"] = False
                        result["details"] = f"SSL Certificate EXPIRED ({abs(days_remaining)} days ago)."
                    else:
                        result["details"] = f"Valid SSL certificate ({days_remaining} days remaining)."

    except Exception as e:
        if "http://" in target_url and not result["is_https"]:
            result["details"] = "HTTP connection used (No SSL/TLS encryption layer)."
        else:
            result["details"] = f"SSL Inspection failed: {str(e)}"

    return result
