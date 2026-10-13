from tools.cisa_tool import cisa_kev_lookup
from tools.otx_tool import otx_lookup

def run_threat_feed_agent(target: str, target_type: str = "ip") -> dict:
    print(f"\n[CorteX] Running Threat Feed Agent on: {target}")

    print("[*] Checking CISA Known Exploited Vulnerabilities...")
    cisa_data = cisa_kev_lookup(target)

    print("[*] Querying OTX AlienVault...")
    otx_data = otx_lookup(target, target_type)

    # Simple threat assessment based on results
    threat_level = "LOW"
    if otx_data.get("pulse_count", 0) > 5:
        threat_level = "MEDIUM"
    if otx_data.get("pulse_count", 0) > 20:
        threat_level = "HIGH"
    if cisa_data.get("matches_found", 0) > 0:
        threat_level = "CRITICAL"     

    report = {
        "target": target,
        "threat_level": threat_level,
        "cisa_kev": cisa_data,
        "otx_alienvault": otx_data
    }

    print(f"[CorteX] Threat Feed Analysis Complete. Threat Level: {threat_level}")
    return report