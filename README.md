# AHM Web Scanner v1.0
> **Automated Web Vulnerability Auditor with Zero False-Positive Engine**

---

##  Developer & Contact Information

* **Developer:** Ahmed Ziyad
* **Role:** Cybersecurity Student & Auditor
* **Contact Email:** ahmedziyad555@gmail.com

---

##  Overview & Capabilities

**AHM Web Scanner** is an automated web security evaluation tool designed to detect vulnerabilities, discover hidden portals, and audit web applications with zero false-positive validation logic.

### 🧩 Included Modules

* **Module 1 (Security Headers - `m1_headers.py`):** Audits missing security headers (HSTS, CSP, X-Frame-Options) and server fingerprints.
* **Module 2 (Sensitive Paths - `m2_paths.py`):** Scans for exposed endpoints, backups, and configurations.
* **Module 3 (Methods & CORS - `m3_methods.py`):** Audits unsafe HTTP methods and cross-origin permissions.
* **Module 4 (Reflected XSS - `m4_xss.py`):** Tests reflected cross-site scripting inputs with verification logic.
* **Module 5 (SQL Injection - `m5_sqli.py`):** Tests dynamic parameters for SQL injection vulnerabilities.
* **Module 6 (Verification Engine - `m6_verifier.py`):** Filters out false positives using real-time HTTP response validation.
* **Module 7 (Subdomain Discovery - `m7_subdomains.py`):** Identifies target subdomains and portals using Certificate Transparency logs.
* **Module 8 (Admin Finder - `m8_admin_finder.py`):** Locates administrative interfaces and login dashboards.
* **Module 9 (Dependencies Audit - `m9_dependencies.py`):** Scans project dependencies for known vulnerabilities and security risks.
* **Module 10 (WAF Detection - `m10_waf.py`):** Detects Web Application Firewalls (WAF) protecting the target server.
* **Module 11 (SSL/TLS Inspector - `m11_ssl.py`):** Checks SSL/TLS configurations, expiration dates, and transport security.
* **📄 PDF Report Generator (`pdf_generator.py`):** Compiles audit findings into a formal PDF report complete with technical details and remediation steps.


---

##  Step-by-Step Installation & Setup

### Prerequisites
* **Python 3.9+** must be installed on your operating system.
* Internet connectivity to install required libraries and perform scans.

---

###  Option 1: Linux / Kali Linux / macOS

1. **Open Terminal** and navigate to the project directory:
   ```bash
   cd AHM_Web_Scanner
   chmod +x run.sh
   ./run.sh

(Alternative manual setup on Linux/Mac):

Bash
python3 -m pip install -r requirements.txt
python3 main.py



# Option 2: Windows

Open the folder.

Double-click on run.bat to automatically install dependencies and launch the scanner.

(Alternative manual setup on Windows Command Prompt / PowerShell):

DOS
pip install -r requirements.txt
python main.py
# Output Reports

All generated PDF assessment reports are stored automatically under the reports/ directory:

Plaintext
AHM_Web_Scanner/
└── reports/
    └── AHM_Scan_Report.pdf

#  Legal Disclaimer & Terms of Use:-
# NOTICE: This tool was developed for educational purposes, defensive security research, and authorized auditing only.
# Usage of AHM Web Scanner against targets without prior written consent, authorization, or explicit legal permission is strictly prohibited.
# The developer (Ahmed Ziyad) accepts no liability for any unauthorized usage or damages resulting from improper execution of this software.


## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
