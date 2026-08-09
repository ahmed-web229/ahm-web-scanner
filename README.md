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

* **Module 1 (Security Headers):** Audits missing security headers (HSTS, CSP, X-Frame-Options) and server fingerprints.
* **Module 2 (Sensitive Paths):** Scans for exposed endpoints, backups, and configurations.
* **Module 3 (Methods & CORS):** Audits unsafe HTTP methods and cross-origin permissions.
* **Module 4 (Reflected XSS):** Tests reflected cross-site scripting inputs with verification logic.
* **Module 5 (SQL Injection):** Tests dynamic parameters for SQL injection vulnerabilities.
* **Module 6 (Verification Engine):** Filters out false positives using real-time HTTP response validation.
* **Module 7 (Subdomain Discovery):** Identifies target subdomains and portals using Certificate Transparency logs.
* **Module 8 (Admin & Portal Finder):** Locates administrative interfaces and login dashboards.
* **Module 9 (Directory Brute-Forcer):** Discovers hidden directory structures and sensitive files.
* **Module 10 (SSL/TLS Scanner):** Inspects SSL certificates, expiration dates, and protocol vulnerabilities.
* **Module 11 (Command Injection Test):** Detects Remote Code Execution (RCE) flaws in parameters.
* **Module 12 (YAML Rules Engine):** Integrates custom detection templates for advanced vulnerability matching.
* **📄 PDF Report Generator:** Compiles audit findings into a formal PDF report complete with technical root causes and remediation recommendations.


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
