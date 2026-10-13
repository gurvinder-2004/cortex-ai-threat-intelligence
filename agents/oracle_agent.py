import os
from groq import Groq
from dotenv import load_dotenv
from tools.shodan_tool import shodan_lookup
from tools.virustotal_tool import virustotal_lookup
from tools.whois_tool import whois_lookup
from tools.cisa_tool import cisa_kev_lookup
from tools.otx_tool import otx_lookup
from tools.darkweb_tool import threatfox_lookup, urlhaus_lookup
load_dotenv()


def gather_oracle_intel(target: str) -> dict:
    """Fast parallel intelligence gathering for ORACLE."""
    print(f"[ORACLE] Gathering intelligence on {target}...")

    results = {}

    try:
        results["shodan"] = shodan_lookup(target)
    except Exception as e:
        results["shodan"] = {"error": str(e)}

    try:
        results["virustotal"] = virustotal_lookup(target)
    except Exception as e:
        results["virustotal"] = {"error": str(e)}

    try:
        results["whois"] = whois_lookup(target)
    except Exception as e:
        results["whois"] = {"error": str(e)}

    try:
        results["cisa_kev"] = cisa_kev_lookup(target)
    except Exception as e:
        results["cisa_kev"] = {"error": str(e)}

    try:
        results["otx"] = otx_lookup(target, "ip")
    except Exception as e:
        results["otx"] = {"error": str(e)}

    try:
        results["threatfox"] = threatfox_lookup(target)
    except Exception as e:
        results["threatfox"] = {"error": str(e)}

    try:
        results["urlhaus"] = urlhaus_lookup(target)
    except Exception as e:
        results["urlhaus"] = {"error": str(e)}

    return results


def build_oracle_prompt(target: str, intel: dict) -> str:
    vt = intel.get("virustotal", {})
    shodan = intel.get("shodan", {})
    whois = intel.get("whois", {})
    otx = intel.get("otx", {})
    cisa = intel.get("cisa_kev", {})
    threatfox = intel.get("threatfox", {})
    urlhaus = intel.get("urlhaus", {})

    return f"""You are ORACLE, CorteX AI's senior threat intelligence analyst. 
Write a comprehensive, professional Cyber Threat Intelligence brief about the following target.
Write it as flowing prose, not as JSON. Be specific, reference the actual data provided.
Use the data below — do not invent facts not present in the data.

═══════════════════════════════════════
TARGET INTELLIGENCE PACKAGE — {target}
═══════════════════════════════════════

VIRUSTOTAL:
- Malicious detections: {vt.get('malicious', 'N/A')}
- Suspicious: {vt.get('suspicious', 'N/A')}
- Harmless: {vt.get('harmless', 'N/A')}
- Reputation score: {vt.get('reputation', 'N/A')} (negative = malicious)
- Tags: {vt.get('tags', [])}
- Country: {vt.get('country', 'N/A')}

SHODAN:
- Organization: {shodan.get('org', 'N/A')}
- Country: {shodan.get('country', 'N/A')}
- Open ports: {shodan.get('open_ports', [])}
- Hostnames: {shodan.get('hostnames', [])}
- Known CVEs: {shodan.get('vulns', [])}
- Tags: {shodan.get('tags', [])}

WHOIS / GEOLOCATION:
- City: {whois.get('city', 'N/A')}, {whois.get('region', 'N/A')}
- ISP: {whois.get('isp', 'N/A')}
- ASN: {whois.get('asn', 'N/A')}
- Timezone: {whois.get('timezone', 'N/A')}

OTX ALIENVAULT:
- Threat pulse count: {otx.get('pulse_count', 0)} (higher = more threat activity)
- Top pulses: {[p.get('name') for p in otx.get('top_pulses', [])[:3]]}
- Malware families: {[p.get('malware_families') for p in otx.get('top_pulses', [])[:2]]}

CISA KEV: {cisa.get('matches_found', 0)} CVE matches in Known Exploited Vulnerabilities catalog
THREATFOX: {threatfox.get('matches_found', 0)} IOC matches
URLHAUS: {urlhaus.get('malicious_urls', 0)} malicious URLs

═══════════════════════════════════════

Write your brief with these sections, each clearly labeled:

## THREAT CLASSIFICATION
One sentence verdict. What is this target?

## EXECUTIVE SUMMARY  
2-3 sentences. What does this mean for a security team?

## TECHNICAL INTELLIGENCE
Detailed breakdown of what the data reveals. Reference specific numbers.
What the open ports suggest. What the CVEs mean. What the VT flags indicate.

## THREAT ACTOR ASSESSMENT
Who is likely operating this infrastructure? What are their probable objectives?
What TTPs are they likely using based on the indicators?

## ACTIVE THREAT INDICATORS
Specific IOCs and what they mean operationally.

## THREAT TIMELINE HYPOTHESIS
Based on the data, reconstruct a likely sequence of threat activity.

## DEFENSIVE RECOMMENDATIONS
5 specific, actionable recommendations. Prioritized by urgency.

## INTELLIGENCE CONFIDENCE
How confident is this assessment and why? What additional data would improve it?

Write in the style of a Mandiant or CrowdStrike threat intelligence report. 
Be precise, analytical, and direct. Do not pad with generic statements."""


def stream_oracle_brief(target: str, intel: dict):
    """Returns a Groq streaming generator for Streamlit to consume."""
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    prompt = build_oracle_prompt(target, intel)

    stream = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        temperature=0.3,
        max_tokens=2000,
        stream=True,
        messages=[
            {
                "role": "system",
                "content": "You are ORACLE, a senior cyber threat intelligence analyst at CorteX AI. "
                           "You write precise, actionable threat intelligence briefs based only on provided data."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    for chunk in stream:
        content = chunk.choices[0].delta.content
        if content:
            yield content