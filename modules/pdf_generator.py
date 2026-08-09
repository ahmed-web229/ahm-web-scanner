#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Module: PDF Report Generator (With SSL/TLS, WAF, Security Score, Remediation & Subdomains)

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

def calculate_security_score(missing_headers, verified_res, ssl_res=None):
    """
    Calculates overall security score (0-100) and risk level based on verified findings and SSL.
    """
    score = 100
    
    # Penalty for unencrypted HTTP or expired SSL
    if ssl_res:
        if not ssl_res.get("is_https"):
            score -= 15
        elif not ssl_res.get("valid"):
            score -= 20

    # Penalties for missing headers
    score -= len(missing_headers) * 3
    
    # Penalties for verified vulnerabilities
    v_paths = verified_res.get("paths", []) if verified_res else []
    v_xss = verified_res.get("xss", []) if verified_res else []
    v_sqli = verified_res.get("sqli", []) if verified_res else []
    
    score -= len(v_paths) * 10
    score -= len(v_xss) * 15
    score -= len(v_sqli) * 25
    
    # Ensure score stays in 0-100 range
    score = max(0, min(100, score))
    
    if score >= 90:
        grade, risk_label, color = "A (EXCELLENT)", "LOW RISK", "#27AE60"
    elif score >= 75:
        grade, risk_label, color = "B (GOOD)", "MEDIUM RISK", "#2980B9"
    elif score >= 50:
        grade, risk_label, color = "C (WARNING)", "HIGH RISK", "#E67E22"
    else:
        grade, risk_label, color = "D (CRITICAL)", "CRITICAL RISK", "#C0392B"
        
    return score, grade, risk_label, color

def generate_pdf_report(target_url, headers_res, cors_res, verified_res, admin_panels=None, dependencies=None, subdomains=None, waf_res=None, ssl_res=None):
    os.makedirs("reports", exist_ok=True)
    pdf_path = "reports/AHM_Scan_Report.pdf"
    
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=16, leading=20, textColor=colors.HexColor("#1A252C"), spaceAfter=12)
    h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=11, leading=15, textColor=colors.HexColor("#2C3E50"), spaceBefore=10, spaceAfter=6, fontName="Helvetica-Bold")
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=8.5, leading=11, textColor=colors.HexColor("#333333"))
    header_table_style = ParagraphStyle('TableHeader', parent=styles['Normal'], fontSize=8.5, leading=10, textColor=colors.white, fontName="Helvetica-Bold")
    
    elements = []
    
    # Header Title
    elements.append(Paragraph("AHM Web Scanner - Vulnerability Assessment Report", title_style))
    
    # Calculate Security Score
    missing = headers_res.get("missing_headers", []) if (headers_res and not headers_res.get("error")) else []
    score, grade, risk_label, score_color = calculate_security_score(missing, verified_res, ssl_res)
    score_p = Paragraph(f"<font color='{score_color}'><b>{score} / 100 - {grade} ({risk_label})</b></font>", body_style)

    # WAF Status Formatting
    waf_status = waf_res.get("waf_name", "None Detected / Direct Connection") if waf_res else "None Detected"
    waf_color = "#C0392B" if (waf_res and waf_res.get("detected")) else "#27AE60"
    waf_p = Paragraph(f"<font color='{waf_color}'><b>{waf_status}</b></font>", body_style)

    # SSL Status Formatting
    if ssl_res and ssl_res.get("is_https"):
        if ssl_res.get("valid"):
            ssl_status = f"HTTPS Active ({ssl_res.get('issuer')}, Exp: {ssl_res.get('expiry_date')} - {ssl_res.get('days_left')} days left)"
            ssl_color = "#27AE60"
        else:
            ssl_status = f"EXPIRED or Invalid SSL ({ssl_res.get('details')})"
            ssl_color = "#C0392B"
    else:
        ssl_status = "Unencrypted HTTP Connection (No SSL/TLS Layer)"
        ssl_color = "#E67E22"
    ssl_p = Paragraph(f"<font color='{ssl_color}'><b>{ssl_status}</b></font>", body_style)

    # Top Information Table
    server_banner = headers_res.get("server", "Generic / Protected") if headers_res else "Not Disclosed"
    tech_stack = headers_res.get("technology", "Not Disclosed") if headers_res else "Not Disclosed"
    
    info_data = [
        [Paragraph("<b>Target URL:</b>", body_style), Paragraph(str(target_url), body_style)],
        [Paragraph("<b>Overall Security Score:</b>", body_style), score_p],
        [Paragraph("<b>SSL/TLS Encryption:</b>", body_style), ssl_p],
        [Paragraph("<b>WAF Protection:</b>", body_style), waf_p],
        [Paragraph("<b>Server Banner:</b>", body_style), Paragraph(str(server_banner), body_style)],
        [Paragraph("<b>Technology Stack:</b>", body_style), Paragraph(str(tech_stack), body_style)],
        [Paragraph("<b>Verification Engine Status:</b>", body_style), Paragraph("<font color='#27AE60'><b>Zero False-Positive Filter Applied</b></font>", body_style)]
    ]
    t_info = Table(info_data, colWidths=[150, 390])
    t_info.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
    ]))
    elements.append(t_info)
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2980B9"), spaceAfter=10))
    
    section_counter = 1

    # 1. Missing Security Headers Audit
    elements.append(Paragraph(f"{section_counter}. Missing Security Headers Audit", h2_style))
    section_counter += 1
    
    if missing:
        h_data = [[
            Paragraph("Header", header_table_style),
            Paragraph("Risk", header_table_style),
            Paragraph("Technical Root Cause", header_table_style)
        ]]
        for m in missing:
            risk_color = "#C0392B" if m.get("risk") == "HIGH" else ("#D35400" if m.get("risk") == "MEDIUM" else "#27AE60")
            risk_p = Paragraph(f"<font color='{risk_color}'><b>{m.get('risk')}</b></font>", body_style)
            h_data.append([
                Paragraph(str(m.get("header")), body_style),
                risk_p,
                Paragraph(str(m.get("root_cause")), body_style)
            ])
            
        t_headers = Table(h_data, colWidths=[150, 60, 330])
        t_headers.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_headers)
    else:
        elements.append(Paragraph("<i>All key security headers are properly configured.</i>", body_style))
    elements.append(Spacer(1, 10))

    # Discovered Subdomains (Module 7)
    if subdomains:
        elements.append(Paragraph(f"{section_counter}. Discovered Subdomains & Portals", h2_style))
        section_counter += 1
        sub_data = [[Paragraph("Status", header_table_style), Paragraph("Discovered Subdomain URL", header_table_style)]]
        for sub in subdomains:
            sub_data.append([Paragraph("<font color='#27AE60'><b>ACTIVE</b></font>", body_style), Paragraph(f"http://{sub}", body_style)])
            
        t_subs = Table(sub_data, colWidths=[100, 440])
        t_subs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_subs)
        elements.append(Spacer(1, 10))

    # Exposed Admin Panels & Login Portals (Module 8)
    if admin_panels is not None:
        elements.append(Paragraph(f"{section_counter}. Exposed Admin Panels & Login Portals", h2_style))
        section_counter += 1
        if admin_panels:
            p_data = [[Paragraph("HTTP Status", header_table_style), Paragraph("Discovered Portal URL", header_table_style)]]
            for p in admin_panels:
                p_data.append([Paragraph(str(p.get("status")), body_style), Paragraph(str(p.get("url")), body_style)])
                
            t_panels = Table(p_data, colWidths=[100, 440])
            t_panels.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(t_panels)
        else:
            elements.append(Paragraph("<i>No exposed administrative panels discovered.</i>", body_style))
        elements.append(Spacer(1, 10))

    # Verified Vulnerabilities (Zero False Positives)
    elements.append(Paragraph(f"{section_counter}. Verified Vulnerabilities (Zero False Positives)", h2_style))
    section_counter += 1
    
    v_paths = verified_res.get("paths", []) if verified_res else []
    v_xss = verified_res.get("xss", []) if verified_res else []
    v_sqli = verified_res.get("sqli", []) if verified_res else []
    
    v_data = [[Paragraph("Type / Location", header_table_style), Paragraph("Risk", header_table_style), Paragraph("Description & Technical Root Cause", header_table_style)]]
    
    for item in v_paths:
        target_path = item.get("url", str(item)) if isinstance(item, dict) else str(item)
        v_data.append([
            Paragraph(f"Sensitive Path:<br/><b>{target_path}</b>", body_style),
            Paragraph("<font color='#E67E22'><b>MEDIUM</b></font>", body_style),
            Paragraph("Exposed sensitive file or administrative endpoint discovered.", body_style)
        ])
        
    for item in v_xss:
        target_xss = item.get("url", str(item)) if isinstance(item, dict) else str(item)
        v_data.append([
            Paragraph(f"Reflected XSS:<br/><b>{target_xss}</b>", body_style),
            Paragraph("<font color='#C0392B'><b>HIGH</b></font>", body_style),
            Paragraph("Unsanitized parameter payload reflection verified in HTTP response body.", body_style)
        ])
        
    for item in v_sqli:
        target_sqli = item.get("url", str(item)) if isinstance(item, dict) else str(item)
        v_data.append([
            Paragraph(f"SQL Injection:<br/><b>{target_sqli}</b>", body_style),
            Paragraph("<font color='#C0392B'><b>CRITICAL</b></font>", body_style),
            Paragraph("Database error signature confirmed via dynamic payload verification.", body_style)
        ])
        
    if len(v_data) > 1:
        t_vulnerabilities = Table(v_data, colWidths=[180, 60, 300])
        t_vulnerabilities.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_vulnerabilities)
    else:
        v_empty_data = [
            [Paragraph("Type / Location", header_table_style), Paragraph("Risk", header_table_style), Paragraph("Description & Technical Root Cause", header_table_style)],
            [Paragraph("None Verified", body_style), Paragraph("<font color='#2980B9'><b>INFO</b></font>", body_style), Paragraph("No high/critical verified vulnerabilities detected on target parameters.", body_style)]
        ]
        t_vulnerabilities = Table(v_empty_data, colWidths=[180, 60, 300])
        t_vulnerabilities.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_vulnerabilities)
        
    elements.append(Spacer(1, 10))

    # Remediation & Defensive Recommendations (GREEN HEADER)
    elements.append(Paragraph(f"{section_counter}. Remediation & Defensive Recommendations", h2_style))
    rem_data = [
        [Paragraph("Category", header_table_style), Paragraph("Recommended Defensive Action", header_table_style)],
        [Paragraph("SSL/TLS Encryption", body_style), Paragraph("Enforce HTTPS with strong TLS 1.2/1.3 protocol suites and install valid SSL certificates issued by a trusted Certificate Authority (CA).", body_style)],
        [Paragraph("Missing Headers", body_style), Paragraph("Configure server headers: Enable Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), and X-Frame-Options to prevent Clickjacking and MITM attacks.", body_style)],
        [Paragraph("Reflected XSS", body_style), Paragraph("Implement contextual output encoding (e.g. htmlspecialchars) and validate all input parameters before rendering them in HTTP responses.", body_style)],
        [Paragraph("SQL Injection", body_style), Paragraph("Use Prepared Statements (Parameterized Queries) for all database operations and enforce Object-Relational Mapping (ORM) where applicable.", body_style)],
        [Paragraph("Exposed Portals", body_style), Paragraph("Restrict administrative endpoints using IP whitelisting, multi-factor authentication (MFA), and Web Application Firewall (WAF) rate limiting.", body_style)]
    ]
    t_rem = Table(rem_data, colWidths=[120, 420])
    t_rem.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#27AE60")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(t_rem)
    
    # Signature Footer
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("<b>Prepared by:</b> Ahmed Ziyad (Cybersecurity Student)", ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor("#2C3E50"), fontName="Helvetica-Bold")))

    doc.build(elements)
    return pdf_path
