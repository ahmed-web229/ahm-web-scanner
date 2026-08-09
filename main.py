#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AHM Web Scanner - Main Execution Script (With Auto-Open PDF, WAF & SSL Inspector)

import sys
import os
import platform
import subprocess
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn

from modules.m1_headers import analyze_headers
from modules.m2_paths import scan_paths
from modules.m3_methods import audit_methods_and_cors
from modules.m4_xss import scan_reflected_xss
from modules.m5_sqli import scan_sqli
from modules.m6_verifier import verify_findings
from modules.m7_subdomains import discover_subdomains
from modules.m8_admin_finder import scan_admin_panels
from modules.m9_dependencies import scan_dependencies
from modules.m10_waf import detect_waf
from modules.m11_ssl import inspect_ssl
from modules.pdf_generator import generate_pdf_report

console = Console()

def print_interface():
    os.system('clear' if os.name == 'posix' else 'cls')
    console.print(Panel("[bold cyan]AHM Web Scanner v1.0[/bold cyan]\n[green]Zero False-Positive Security Auditor[/green]", expand=False))

def clean_url(raw_url: str) -> str:
    cleaned = raw_url.strip("()[]'\" ")
    while cleaned.startswith("http://") or cleaned.startswith("https://"):
        if cleaned.startswith("https://"):
            cleaned = cleaned[8:]
        elif cleaned.startswith("http://"):
            cleaned = cleaned[7:]
    cleaned = cleaned.strip('/')
    return f"http://{cleaned}"

def open_pdf_report(pdf_path: str):
    """
    Automatically opens the generated PDF report based on the operating system.
    """
    console.print("[bold yellow][*] Opening PDF Report automatically...[/bold yellow]")
    try:
        current_os = platform.system()
        if current_os == "Linux":
            subprocess.run(["xdg-open", pdf_path], check=False)
        elif current_os == "Darwin":  # macOS
            subprocess.run(["open", pdf_path], check=False)
        elif current_os == "Windows":
            os.startfile(pdf_path)
    except Exception as e:
        console.print(f"[bold red][!] Could not auto-open PDF report: {e}[/bold red]")

def main():
    print_interface()

    raw_input = Prompt.ask("\n[bold yellow][?] Enter target URL to scan[/bold yellow]")
    if not raw_input.strip():
        console.print("[bold red][!] Target URL cannot be empty.[/bold red]")
        sys.exit(1)
        
    target_url = clean_url(raw_input)

    console.print("\n[bold cyan]Select Scan Type:[/bold cyan]")
    console.print(" [1] [bold green]Fast Scan[/bold green]           (Headers, Sensitive Paths & CORS)")
    console.print(" [2] [bold red]Full Deep Scan[/bold red]      (All Vulnerability Modules + Portals + WAF + SSL Inspector)")
    console.print(" [3] [bold magenta]Subdomain Discovery[/bold magenta]   (Find target subdomains & portals)")
    console.print(" [4] [bold blue]Admin & Portal Finder[/bold blue] (Scan for login panels & dashboards)")
    
    scan_choice = Prompt.ask("\n[bold yellow][?] Choose Option[/bold yellow]", choices=["1", "2", "3", "4"], default="2")

    console.print(f"\n[bold cyan][*] Target set to:[/bold cyan] {target_url}\n")

    if scan_choice == "3":
        console.print("[yellow][*] Gathering Subdomains...[/yellow]\n")
        subs = discover_subdomains(target_url)
        if subs:
            console.print(f"[bold green][✓] Found {len(subs)} Subdomains/Portals:[/bold green]\n")
            for sub in subs:
                console.print(f"  [cyan]• http://{sub}[/cyan]")
        else:
            console.print("[red][!] No subdomains found or service unavailable.[/red]")
        return

    if scan_choice == "4":
        console.print("[yellow][*] Scanning for Admin Panels & Portals...[/yellow]\n")
        panels = scan_admin_panels(target_url)
        if panels:
            console.print(f"[bold green][✓] Found {len(panels)} Portals/Panels:[/bold green]\n")
            for p in panels:
                console.print(f"  [cyan]• [{p['status']}] {p['url']}[/cyan]")
        else:
            console.print("[red][!] No exposed admin panels found.[/red]")
        return

    m1_res = {}
    m2_res = []
    m3_res = {}
    m4_res = []
    m5_res = []
    m7_res = []
    m8_res = []
    m9_res = []
    m10_res = {}
    m11_res = {}
    verified_res = {}

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=False) as progress:
        
        # Module 11: SSL/TLS Inspector
        progress.add_task(description="[yellow]Running Module 11: SSL/TLS Inspector...[/yellow]", total=None)
        m11_res = inspect_ssl(target_url)

        # Module 10: WAF Detection
        progress.add_task(description="[yellow]Running Module 10: WAF Detection Engine...[/yellow]", total=None)
        m10_res = detect_waf(target_url)

        # Module 1
        progress.add_task(description="[yellow]Running Module 1: Headers & Fingerprinting...[/yellow]", total=None)
        m1_res = analyze_headers(target_url)

        # Module 2
        progress.add_task(description="[yellow]Running Module 2: Sensitive Paths Scanner...[/yellow]", total=None)
        m2_res = scan_paths(target_url)

        # Module 3
        progress.add_task(description="[yellow]Running Module 3: Methods & CORS Audit...[/yellow]", total=None)
        m3_res = audit_methods_and_cors(target_url)

        if scan_choice == "2":
            # Module 4
            progress.add_task(description="[yellow]Running Module 4: Reflected XSS Engine...[/yellow]", total=None)
            m4_res = scan_reflected_xss(target_url)

            # Module 5
            progress.add_task(description="[yellow]Running Module 5: SQL Injection Engine...[/yellow]", total=None)
            m5_res = scan_sqli(target_url)

            # Module 7
            progress.add_task(description="[yellow]Running Module 7: Subdomain Discovery...[/yellow]", total=None)
            m7_res = discover_subdomains(target_url)

            # Module 8
            progress.add_task(description="[yellow]Running Module 8: Admin & Portal Finder...[/yellow]", total=None)
            m8_res = scan_admin_panels(target_url)

            # Module 9
            progress.add_task(description="[yellow]Running Module 9: Dependency & CVE Scanner...[/yellow]", total=None)
            m9_res = scan_dependencies(target_url)

            # Module 6: Verification
            progress.add_task(description="[bold green]Running Module 6: Central Verification Engine...[/bold green]", total=None)
            verified_res = verify_findings(
                m2_res=m2_res, 
                m4_res=m4_res, 
                m5_res=m5_res, 
                m1_res=m1_res, 
                m3_res=m3_res, 
                m8_res=m8_res, 
                m9_res=m9_res
            )
        else:
            verified_res["headers"] = m1_res
            verified_res["paths"] = m2_res
            verified_res["cors"] = m3_res

        # Report Generation
        progress.add_task(description="[bold cyan]Generating PDF Report...[/bold cyan]", total=None)
        pdf_file = generate_pdf_report(
            target_url, 
            verified_res.get("headers", m1_res), 
            verified_res.get("cors", m3_res), 
            verified_res, 
            admin_panels=verified_res.get("admin_panels", m8_res), 
            dependencies=verified_res.get("dependencies", m9_res),
            subdomains=m7_res,
            waf_res=m10_res,
            ssl_res=m11_res
        )

    console.print("\n[bold green][✓] Scan Completed Successfully![/bold green]")
    console.print(f"[bold white][+] PDF Report generated at:[/bold white] [cyan]{pdf_file}[/cyan]\n")

    # Auto-open PDF Report after scanning
    if pdf_file and os.path.exists(pdf_file):
        open_pdf_report(pdf_file)

if __name__ == "__main__":
    main()

# =====================================================
# Prepared by: AHMED ZIYAD (Cybersecurity Student)
# Version: 1.0
# Note: All tests performed responsibly.
# Contact Information: ahmedziyad555@gmail.com
# =====================================================
