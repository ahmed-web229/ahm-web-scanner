#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AHM Web Scanner - Module 8: Admin & Portal Finder

import httpx
from urllib.parse import urljoin

ADMIN_PATHS = [
    "admin/", "admin/login.php", "admin/index.php", "login/", "login.php",
    "portal/", "dashboard/", "cpanel/", "user/login", "administrator/",
    "staff/", "teacher/", "student/", "api/v1/", "manage/"
]

def scan_admin_panels(target_url: str) -> list:
    found_panels = []
    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
    }

    with httpx.Client(verify=False, timeout=10.0, follow_redirects=True, headers=headers_req) as client:
        for path in ADMIN_PATHS:
            test_url = urljoin(target_url, path)
            try:
                resp = client.get(test_url)
                if resp.status_code in [200, 301, 302, 401, 403]:
                    found_panels.append({
                        "url": test_url,
                        "status": resp.status_code,
                        "path": path
                    })
            except Exception:
                continue

    return found_panels
