from tools.darkweb_tool import ransomware_live_lookup, threatfox_lookup, urlhaus_lookup

def run_darkweb_agent(target: str) -> dict:
    print(f"\n[CorteX] Running Dark Web Monitoring on: {target}")

    print("[*] Checking Ransomware.live leak sites...")
    ransomware_data = ransomware_live_lookup(target)

    print("[*] Checking ThreatFox IOC database...")
    threatfox_data = threatfox_lookup(target)

    print("[*] Checking URLhaus malware database...")
    urlhaus_data = urlhaus_lookup(target)

    dark_web_score = 0
    if ransomware_data.get("matches_found", 0) > 0:
        dark_web_score += 50
    if threatfox_data.get("matches_found", 0) > 0:
        dark_web_score += 30
    if urlhaus_data.get("malicious_urls", 0) > 0:
        dark_web_score += 20

    report = {
        "target": target,
        "dark_web_exposure_score": dark_web_score,
        "exposure_level": "HIGH" if dark_web_score >= 50 else "MEDIUM" if dark_web_score >= 20 else "LOW",
        "ransomware_leaks": ransomware_data,
        "threatfox": threatfox_data,
        "urlhaus": urlhaus_data
    }

    print(f"[CorteX] Dark Web Scan Complete. Exposure Level: {report['exposure_level']}")
    return report