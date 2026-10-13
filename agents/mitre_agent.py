import os, json
from groq import Groq
from dotenv import load_dotenv
load_dotenv()

MITRE_TECHNIQUES = {
    "T1595": "Active Scanning", "T1592": "Gather Victim Host Info",
    "T1589": "Gather Victim Identity Info", "T1566": "Phishing",
    "T1190": "Exploit Public-Facing Application", "T1133": "External Remote Services",
    "T1059": "Command and Scripting Interpreter", "T1078": "Valid Accounts",
    "T1486": "Data Encrypted for Impact (Ransomware)", "T1041": "Exfiltration Over C2",
    "T1071": "Application Layer Protocol", "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery", "T1057": "Process Discovery",
    "T1105": "Ingress Tool Transfer", "T1027": "Obfuscated Files or Information",
    "T1560": "Archive Collected Data", "T1110": "Brute Force",
    "T1046": "Network Service Discovery", "T1018": "Remote System Discovery",
}

def _rule_based_risk(osint: dict, threats: dict, darkweb: dict) -> tuple[int, str, str]:
    """Hardcoded scoring that ALWAYS works regardless of LLM."""
    score = 0
    tactic = "Reconnaissance"
    stage = "Reconnaissance"

    vt = osint.get("virustotal", {})
    malicious = vt.get("malicious", 0)
    reputation = vt.get("reputation", 0)
    tags = [t.lower() for t in vt.get("tags", [])]
    vulns = osint.get("shodan", {}).get("vulns", [])
    open_ports = osint.get("shodan", {}).get("open_ports", [])
    pulse_count = threats.get("otx_alienvault", {}).get("pulse_count", 0)
    dark_score = darkweb.get("dark_web_exposure_score", 0)
    threatfox_hits = darkweb.get("threatfox", {}).get("matches_found", 0)
    cisa_hits = threats.get("cisa_kev", {}).get("matches_found", 0)

    # VirusTotal scoring
    if malicious > 15: score += 40
    elif malicious > 10: score += 30
    elif malicious > 5: score += 20
    elif malicious > 0: score += 10

    # Reputation
    if reputation < -20: score += 20
    elif reputation < -10: score += 10

    # Tags
    if "tor" in tags: score += 15; tactic = "Defense Evasion"; stage = "Command and Control"
    if "malware" in tags: score += 20; tactic = "Execution"
    if "ransomware" in tags: score += 30; tactic = "Impact"; stage = "Exfiltration"
    if "botnet" in tags: score += 25; tactic = "Command and Control"
    if "phishing" in tags: score += 20; tactic = "Initial Access"

    # OTX
    if pulse_count > 20: score += 20
    elif pulse_count > 5: score += 12
    elif pulse_count > 0: score += 6

    # Vulnerabilities
    if len(vulns) > 3: score += 25; stage = "Exploitation"
    elif len(vulns) > 0: score += 15; stage = "Exploitation"

    # Ports — sensitive services
    sensitive_ports = {22, 3389, 445, 21, 23, 3306, 5432, 6379, 27017}
    exposed_sensitive = len(set(open_ports) & sensitive_ports)
    if exposed_sensitive > 2: score += 15
    elif exposed_sensitive > 0: score += 8

    # Dark web
    if dark_score > 50: score += 20
    elif dark_score > 20: score += 10
    if threatfox_hits > 0: score += 15
    if cisa_hits > 0: score += 25; stage = "Exploitation"

    return min(score, 100), tactic, stage


def run_mitre_agent(osint_data: dict, threat_data: dict, darkweb_data: dict) -> dict:
    print(f"\n[CorteX] Running MITRE ATT&CK Mapping Agent...")

    # Always compute rule-based score first — this NEVER fails
    risk_score, primary_tactic, attack_stage = _rule_based_risk(
        osint_data or {}, threat_data or {}, darkweb_data or {}
    )

    # Build fallback techniques from rule-based data
    fallback_techniques = []
    vt = (osint_data or {}).get("virustotal", {})
    tags = [t.lower() for t in vt.get("tags", [])]
    malicious = vt.get("malicious", 0)

    if malicious > 0 or tags:
        fallback_techniques.append({
            "technique_id": "T1592",
            "technique_name": "Gather Victim Host Info",
            "confidence": "HIGH" if malicious > 10 else "MEDIUM",
            "rationale": f"Target has {malicious} malicious VT flags"
        })
    if "tor" in tags:
        fallback_techniques.append({
            "technique_id": "T1090",
            "technique_name": "Proxy: Multi-hop Proxy",
            "confidence": "HIGH",
            "rationale": "Target tagged as Tor infrastructure"
        })
    if (osint_data or {}).get("shodan", {}).get("vulns"):
        fallback_techniques.append({
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "confidence": "HIGH",
            "rationale": f"Known CVEs found: {osint_data['shodan']['vulns'][:3]}"
        })

    # Try LLM enhancement — if it fails, we still have good data
    try:
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))

        context = f"""
Target OSINT:
- VirusTotal malicious flags: {vt.get('malicious', 0)}
- VirusTotal reputation: {vt.get('reputation', 0)}
- VirusTotal tags: {vt.get('tags', [])}
- Open ports: {(osint_data or {}).get('shodan', {}).get('open_ports', [])}
- Known CVEs: {(osint_data or {}).get('shodan', {}).get('vulns', [])}
- OTX pulse count: {(threat_data or {}).get('otx_alienvault', {}).get('pulse_count', 0)}
- Dark web exposure: {(darkweb_data or {}).get('exposure_level', 'LOW')}
- ThreatFox IOC hits: {(darkweb_data or {}).get('threatfox', {}).get('matches_found', 0)}
"""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": "You are a MITRE ATT&CK expert. Respond only with valid JSON."
                },
                {
                    "role": "user",
                    "content": f"""Based on this threat intelligence, map 3-5 MITRE ATT&CK techniques.

{context}

Respond with this exact JSON structure:
{{
    "mapped_techniques": [
        {{
            "technique_id": "T1xxx",
            "technique_name": "technique name",
            "confidence": "HIGH or MEDIUM or LOW",
            "rationale": "one sentence explanation"
        }}
    ]
}}"""
                }
            ]
        )

        data = json.loads(response.choices[0].message.content)
        techniques = data.get("mapped_techniques", fallback_techniques)
        if not techniques:
            techniques = fallback_techniques

    except Exception as e:
        print(f"[MITRE] LLM failed, using rule-based: {e}")
        techniques = fallback_techniques

    result = {
        "risk_score": risk_score,
        "primary_tactic": primary_tactic,
        "attack_stage": attack_stage,
        "mapped_techniques": techniques
    }

    print(f"[CorteX] MITRE Mapping Complete. Risk: {risk_score}/100, Tactic: {primary_tactic}")
    return result