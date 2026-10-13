from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import json
from datetime import datetime
import os

def generate_report(target: str, osint: dict, threats: dict, darkweb: dict, mitre: dict, profile: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/CorteX_CTI_Report_{target.replace('.', '_')}_{timestamp}.pdf"

    doc = SimpleDocTemplate(filename, pagesize=A4,
                            rightMargin=50, leftMargin=50,
                            topMargin=50, bottomMargin=50)

    styles = getSampleStyleSheet()
    NAVY = HexColor("#1F4E79")
    AMBER = HexColor("#F59E0B")
    RED = HexColor("#DC2626")
    GREEN = HexColor("#16A34A")
    LIGHT_BLUE = HexColor("#EBF3FB")

    title_style = ParagraphStyle('title', fontSize=22, textColor=white, alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=6)
    subtitle_style = ParagraphStyle('subtitle', fontSize=11, textColor=white, alignment=TA_CENTER, fontName='Helvetica')
    h1_style = ParagraphStyle('h1', fontSize=14, textColor=NAVY, fontName='Helvetica-Bold', spaceBefore=16, spaceAfter=6, borderPad=4)
    normal_style = ParagraphStyle('normal', fontSize=10, textColor=black, fontName='Helvetica', spaceAfter=4, leading=14)
    bold_style = ParagraphStyle('bold', fontSize=10, textColor=black, fontName='Helvetica-Bold', spaceAfter=4)

    story = []

    # Header Banner
    header_data = [
        [Paragraph("CorteX AI — Cyber Threat Intelligence Report", title_style)],
        [Paragraph(f"Target: {target} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style)]
    ]
    header_table = Table(header_data, colWidths=[6.3*inch])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), NAVY),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [NAVY, NAVY]),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING', (0,0), (-1,-1), 16),
        ('RIGHTPADDING', (0,0), (-1,-1), 16),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 16))

    # Threat Rating Banner
    rating = profile.get("overall_threat_rating", "UNKNOWN")
    rating_color = RED if rating in ["CRITICAL", "HIGH"] else HexColor("#F59E0B") if rating == "MEDIUM" else GREEN
    rating_data = [[Paragraph(f"OVERALL THREAT RATING: {rating}", ParagraphStyle('rating', fontSize=16, textColor=white, fontName='Helvetica-Bold', alignment=TA_CENTER))]]
    rating_table = Table(rating_data, colWidths=[6.3*inch])
    rating_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), rating_color),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(rating_table)
    story.append(Spacer(1, 16))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 6))
    summary = profile.get("analyst_summary", "No summary available.")
    story.append(Paragraph(summary, normal_style))
    story.append(Spacer(1, 12))

    # OSINT Summary Table
    story.append(Paragraph("2. OSINT Reconnaissance Results", h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 6))

    shodan = osint.get("shodan", {})
    vt = osint.get("virustotal", {})
    whois = osint.get("whois", {})

    osint_data = [
        ["Field", "Value"],
        ["Target IP", target],
        ["Organization", shodan.get("org", "N/A")],
        ["Country", whois.get("country", "N/A")],
        ["ISP", whois.get("isp", "N/A")],
        ["Open Ports", str(shodan.get("open_ports", []))],
        ["Hostnames", str(shodan.get("hostnames", []))],
        ["Known CVEs", str(shodan.get("vulns", "None"))],
        ["VT Malicious Flags", str(vt.get("malicious", 0))],
        ["VT Reputation Score", str(vt.get("reputation", 0))],
    ]
    osint_table = Table(osint_data, colWidths=[2.2*inch, 4.1*inch])
    osint_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [LIGHT_BLUE, white]),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, HexColor("#CCCCCC")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(osint_table)
    story.append(Spacer(1, 12))

    # Threat Intelligence
    story.append(Paragraph("3. Threat Intelligence Analysis", h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 6))

    threat_data = [
        ["Source", "Finding"],
        ["Threat Level", threats.get("threat_level", "N/A")],
        ["CISA KEV Matches", str(threats.get("cisa_kev", {}).get("matches_found", 0))],
        ["OTX Pulse Count", str(threats.get("otx_alienvault", {}).get("pulse_count", 0))],
        ["Dark Web Exposure", darkweb.get("exposure_level", "N/A")],
        ["Ransomware Mentions", str(darkweb.get("ransomware_leaks", {}).get("matches_found", 0))],
        ["ThreatFox IOCs", str(darkweb.get("threatfox", {}).get("matches_found", 0))],
        ["URLhaus Malicious URLs", str(darkweb.get("urlhaus", {}).get("malicious_urls", 0))],
    ]
    threat_table = Table(threat_data, colWidths=[2.2*inch, 4.1*inch])
    threat_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [LIGHT_BLUE, white]),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, HexColor("#CCCCCC")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(threat_table)
    story.append(Spacer(1, 12))

    # MITRE ATT&CK
    story.append(Paragraph("4. MITRE ATT&CK Mapping", h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Primary Tactic:</b> {mitre.get('primary_tactic', 'N/A')}", normal_style))
    story.append(Paragraph(f"<b>Attack Stage:</b> {mitre.get('attack_stage', 'N/A')}", normal_style))
    story.append(Paragraph(f"<b>Risk Score:</b> {mitre.get('risk_score', 'N/A')}/100", normal_style))
    story.append(Spacer(1, 6))

    techniques = mitre.get("mapped_techniques", [])
    if techniques:
        mitre_data = [["Technique ID", "Name", "Confidence", "Rationale"]]
        for t in techniques:
            mitre_data.append([
                t.get("technique_id", ""),
                t.get("technique_name", ""),
                t.get("confidence", ""),
                Paragraph(t.get("rationale", "")[:150], ParagraphStyle('small', fontSize=8))
            ])
        mitre_table = Table(mitre_data, colWidths=[1*inch, 1.5*inch, 0.9*inch, 2.9*inch])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), NAVY),
            ('TEXTCOLOR', (0,0), (-1,0), white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [LIGHT_BLUE, white]),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor("#CCCCCC")),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(mitre_table)
    story.append(Spacer(1, 12))

    # Threat Actor Profile
    story.append(Paragraph("5. Threat Actor Profile", h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 6))

    profile_fields = [
        ("Actor Type", "threat_actor_type"),
        ("Sophistication", "sophistication_level"),
        ("Motivation", "likely_motivation"),
        ("Infrastructure", "infrastructure_assessment"),
        ("Victimology", "victimology"),
    ]
    for label, key in profile_fields:
        story.append(Paragraph(f"<b>{label}:</b> {profile.get(key, 'N/A')}", normal_style))

    story.append(Spacer(1, 8))
    predicted = profile.get("predicted_next_actions", [])
    if predicted:
        story.append(Paragraph("<b>Predicted Next Actions:</b>", bold_style))
        for action in predicted:
            story.append(Paragraph(f"• {action}", normal_style))

    story.append(Spacer(1, 8))
    defenses = profile.get("recommended_defenses", [])
    if defenses:
        story.append(Paragraph("<b>Recommended Defenses:</b>", bold_style))
        for defense in defenses:
            story.append(Paragraph(f"• {defense}", normal_style))

    # Footer
    story.append(Spacer(1, 20))
    footer_data = [[Paragraph("Generated by CorteX AI — Autonomous Multi-Agent Cyber Threat Intelligence Platform | MBSCET 2025-2026",
                               ParagraphStyle('footer', fontSize=8, textColor=white, alignment=TA_CENTER))]]
    footer_table = Table(footer_data, colWidths=[6.3*inch])
    footer_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), NAVY),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(footer_table)

    doc.build(story)
    print(f"[CorteX] CTI Report saved: {filename}")
    return filename