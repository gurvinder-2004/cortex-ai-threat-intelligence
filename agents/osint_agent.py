from tools.shodan_tool import shodan_lookup
from tools.virustotal_tool import virustotal_lookup
from tools.whois_tool import whois_lookup

def run_osint_agent(target: str) -> dict:
    print(f"\n[CorteX] Running OSINT Recon on: {target}")
    print("[*] Querying Shodan...")
    shodan_data = shodan_lookup(target)

    print("[*] Querying VirusTotal...")
    vt_data = virustotal_lookup(target)

    print("[*] Querying WHOIS/GeoIP...")
    whois_data = whois_lookup(target)

    report = {
        "target": target,
        "shodan": shodan_data,
        "virustotal": vt_data,
        "whois": whois_data
    }

    print("\n[CorteX] OSINT Recon Complete.")
    return report