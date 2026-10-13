import os, json
from groq import Groq
from dotenv import load_dotenv
load_dotenv()


def _rule_based_profile(target: str, osint: dict, threats: dict, darkweb: dict, mitre: dict) -> dict:
    """Hardcoded profile that ALWAYS works."""
    vt = (osint or {}).get("virustotal", {})
    malicious = vt.get("malicious", 0)
    reputation = vt.get("reputation", 0)
    tags = [t.lower() for t in vt.get("tags", [])]
    pulse_count = (threats or {}).get("otx_alienvault", {}).get("pulse_count", 0)
    risk_score = (mitre or {}).get("risk_score", 0)
    dark_score = (darkweb or {}).get("dark_web_exposure_score", 0)
    vulns = (osint or {}).get("shodan", {}).get("vulns", [])
    org = (osint or {}).get("shodan", {}).get("org", "Unknown")
    country = (osint or {}).get("whois", {}).get("country", "Unknown")

    # Determine threat rating from hard data
    if risk_score >= 70 or malicious > 15 or "ransomware" in tags:
        rating = "CRITICAL"
    elif risk_score >= 45 or malicious > 8 or pulse_count > 20 or dark_score > 50:
        rating = "HIGH"
    elif risk_score >= 20 or malicious > 2 or pulse_count > 3 or "tor" in tags:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    # Actor type
    if "tor" in tags:
        actor_type = "Infrastructure / Anonymization Node"
        motivation = "Operational Security — Attack Anonymization"
        sophistication = "MEDIUM"
    elif "ransomware" in tags or dark_score > 50:
        actor_type = "Cybercriminal / Ransomware Operator"
        motivation = "Financial"
        sophistication = "HIGH"
    elif "botnet" in tags or "malware" in tags:
        actor_type = "Malware Infrastructure"
        motivation = "Financial / Espionage"
        sophistication = "HIGH"
    elif malicious > 10:
        actor_type = "Known Malicious Actor"
        motivation = "Unknown"
        sophistication = "MEDIUM"
    elif malicious > 0:
        actor_type = "Suspicious Infrastructure"
        motivation = "Unknown"
        sophistication = "LOW"
    else:
        actor_type = "Unclassified"
        motivation = "Unknown"
        sophistication = "LOW"

    summary = (
        f"Target {target} ({org}, {country}) presents a {rating} threat profile. "
        f"VirusTotal reports {malicious} malicious detections with reputation score {reputation}. "
    )
    if "tor" in tags:
        summary += "The target is confirmed Tor exit node infrastructure, commonly used by threat actors for anonymization. "
    if vulns:
        summary += f"Known CVEs include: {', '.join(vulns[:3])}. "
    if pulse_count > 0:
        summary += f"Referenced in {pulse_count} OTX threat intelligence pulses. "
    summary += f"MITRE ATT&CK risk score: {risk_score}/100."

    return {
        "threat_actor_type": actor_type,
        "sophistication_level": sophistication,
        "likely_motivation": motivation,
        "infrastructure_assessment": f"{org} infrastructure in {country}",
        "victimology": "Organizations and individuals using this infrastructure as attack vector",
        "predicted_next_actions": [
            "Continue scanning for vulnerable targets",
            "Leverage anonymization for attack operations" if "tor" in tags else "Probe exposed services",
            "Potential credential harvesting or data exfiltration"
        ],
        "recommended_defenses": [
            f"Block {target} at perimeter firewall immediately" if malicious > 5 else "Monitor traffic from this IP",
            "Enable geo-blocking for high-risk regions",
            "Deploy intrusion detection rules for associated IOCs",
            "Patch all identified CVEs" if vulns else "Conduct regular vulnerability assessments"
        ],
        "overall_threat_rating": rating,
        "analyst_summary": summary
    }


def run_profiling_agent(target: str, osint: dict, threats: dict, darkweb: dict, mitre: dict) -> dict:
    print(f"\n[CorteX] Running Threat Actor Profiling Agent...")

    # Rule-based profile — ALWAYS works
    profile = _rule_based_profile(target, osint, threats, darkweb, mitre)

    # Try LLM enhancement for analyst summary only
    try:
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cyber threat intelligence analyst. Respond only with valid JSON."
                },
                {
                    "role": "user",
                    "content": f"""Enhance this threat profile with deeper analysis.

Target: {target}
Current profile: {json.dumps(profile, indent=2)}

Provide enhanced analysis as JSON:
{{
    "predicted_next_actions": ["action1", "action2", "action3"],
    "recommended_defenses": ["defense1", "defense2", "defense3"],
    "analyst_summary": "3-4 professional sentences"
}}"""
                }
            ]
        )

        enhancement = json.loads(response.choices[0].message.content)
        profile["predicted_next_actions"] = enhancement.get("predicted_next_actions", profile["predicted_next_actions"])
        profile["recommended_defenses"] = enhancement.get("recommended_defenses", profile["recommended_defenses"])
        profile["analyst_summary"] = enhancement.get("analyst_summary", profile["analyst_summary"])

    except Exception as e:
        print(f"[Profiling] LLM enhancement failed, using rule-based: {e}")

    print(f"[CorteX] Profiling Complete. Rating: {profile['overall_threat_rating']}")
    return profile