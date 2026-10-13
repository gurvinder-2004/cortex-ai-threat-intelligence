import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def cisa_kev_lookup(target: str) -> dict:
    """
    Checks if any CVEs related to the target appear in CISA's 
    Known Exploited Vulnerabilities catalog
    """
    try:
        print("[*] Fetching CISA KEV catalog...")
        response = requests.get(CISA_KEV_URL, timeout=15)

        if response.status_code != 200:
            return {"error": f"CISA KEV fetch failed: {response.status_code}"}

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        # Search for target string in vendor/product/description fields
        matches = []
        target_lower = target.lower()

        for vuln in vulnerabilities:
            searchable = (
                vuln.get("vendorProject", "") + " " +
                vuln.get("product", "") + " " +
                vuln.get("shortDescription", "") + " " +
                vuln.get("vulnerabilityName", "")
            ).lower()

            if target_lower in searchable:
                matches.append({
                    "cve_id": vuln.get("cveID"),
                    "name": vuln.get("vulnerabilityName"),
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "date_added": vuln.get("dateAdded"),
                    "due_date": vuln.get("dueDate"),
                    "severity": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    "description": vuln.get("shortDescription", "")[:200]
                })

        return {
            "target": target,
            "total_kev_entries": len(vulnerabilities),
            "matches_found": len(matches),
            "matches": matches[:10]  # top 10 matches
        }

    except Exception as e:
        return {"error": str(e)}