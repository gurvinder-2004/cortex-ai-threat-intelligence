import requests
import re


def _is_ip(target: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))


def ransomware_live_lookup(target: str) -> dict:
    """Search Ransomware.live for victim mentions matching the target"""
    base = {"source": "Ransomware.live", "matches_found": 0, "matches": []}

    # For raw IPs, Ransomware.live won't have matches (it tracks company victims by name)
    # Try to extract a meaningful search term
    search_term = target.lower()
    if _is_ip(target):
        # IPs don't appear in ransomware victim lists — return clean no-match
        return {**base, "note": "IP addresses not tracked in ransomware victim databases — domain/org name needed"}

    # Strip www. and TLD for better matching
    domain_core = re.sub(r'^www\.', '', search_term)
    domain_core = re.sub(r'\.(com|org|net|io|co|gov|edu)$', '', domain_core)

    # Try the correct current Ransomware.live endpoints
    endpoints = [
        ("GET",  f"https://api.ransomware.live/v2/victims/recent", None),
        ("GET",  f"https://api.ransomware.live/victims/recent",    None),
        ("GET",  f"https://api.ransomware.live/v2/recentvictims",  None),
    ]

    victims = None
    for method, url, payload in endpoints:
        try:
            r = requests.get(url, timeout=12, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                data = r.json()
                # API returns either a list or {"victims": [...]}
                victims = data if isinstance(data, list) else data.get("victims", data.get("data", []))
                if victims:
                    break
        except Exception:
            continue

    if victims is None:
        return {**base, "note": "API temporarily unavailable"}

    matches = []
    for v in victims:
        victim_name = str(v.get("victim", v.get("name", ""))).lower()
        website = str(v.get("website", v.get("url", ""))).lower()
        desc = str(v.get("description", "")).lower()
        if domain_core in victim_name or domain_core in website or search_term in desc:
            matches.append({
                "victim": v.get("victim", v.get("name", "Unknown")),
                "group": v.get("group", v.get("gang", "Unknown")),
                "date": v.get("published", v.get("date", "N/A")),
                "country": v.get("country", "N/A"),
                "website": v.get("website", ""),
                "description": str(v.get("description", ""))[:200],
            })

    return {**base, "matches_found": len(matches), "matches": matches[:5]}


def threatfox_lookup(target: str) -> dict:
    """Check IOCs against ThreatFox (abuse.ch) — IPs, domains, URLs, hashes"""
    base = {"source": "ThreatFox", "matches_found": 0, "iocs": []}
    try:
        # ThreatFox expects exact IOC format
        payload = {"query": "search_ioc", "search_term": target}
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code != 200:
            return {**base, "note": f"ThreatFox API status {r.status_code}"}

        data = r.json()
        status = data.get("query_status", "")

        if status in ("no_results", "ok") and not data.get("data"):
            return base  # clean no-match

        iocs = []
        for item in (data.get("data") or [])[:8]:
            iocs.append({
                "ioc": item.get("ioc"),
                "ioc_type": item.get("ioc_type"),
                "threat_type": item.get("threat_type"),
                "malware": item.get("malware"),
                "malware_printable": item.get("malware_printable"),
                "confidence": item.get("confidence_level"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "tags": item.get("tags", []),
            })

        return {**base, "matches_found": len(iocs), "iocs": iocs}
    except Exception as e:
        return {**base, "note": str(e)}


def urlhaus_lookup(target: str) -> dict:
    """Check if target IP/domain appears in URLhaus malware URL database"""
    base = {"source": "URLhaus", "malicious_urls": 0, "urls": []}
    try:
        # URLhaus accepts both IPs and domains in the 'host' field
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": target},
            timeout=12,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code != 200:
            return {**base, "note": f"URLhaus API status {r.status_code}"}

        data = r.json()
        if data.get("query_status") in ("no_results", "is_whitelisted"):
            return base  # clean

        urls = []
        for url in (data.get("urls") or [])[:8]:
            urls.append({
                "url": url.get("url"),
                "status": url.get("url_status"),
                "threat": url.get("threat"),
                "date_added": url.get("date_added", "")[:10],
                "tags": url.get("tags") or [],
            })

        blacklists = data.get("blacklists", {})
        return {
            **base,
            "malicious_urls": len(urls),
            "urls": urls,
            "blacklisted_surbl": blacklists.get("surbl", ""),
            "blacklisted_gsb": blacklists.get("gsb", ""),
        }
    except Exception as e:
        return {**base, "note": str(e)}
