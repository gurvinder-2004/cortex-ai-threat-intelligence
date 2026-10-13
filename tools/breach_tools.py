import requests
import time
import os
import socket
import re
from dotenv import load_dotenv

load_dotenv()

try:
    import dns.resolver as _dns_resolver
    _DNS_AVAILABLE = True
except ImportError:
    _dns_resolver = None  # type: ignore
    _DNS_AVAILABLE = False


# ─── HELPERS ─────────────────────────────────────────────────
def _normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].split('?')[0]
    if '.' not in domain:
        domain = domain + '.com'
    return domain


def _headers(extra: dict = {}) -> dict:
    base = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    return {**base, **extra}


# ─── LEAKCHECK EMAIL ─────────────────────────────────────────
def leakcheck_email(email: str) -> dict:
    api_key = os.getenv("LEAKCHECK_API_KEY", "")
    if not api_key:
        return {"error": "no_key", "found": False, "breach_count": 0, "breaches": []}
    try:
        r = requests.get(
            "https://leakcheck.io/api/v2/query",
            params={"key": api_key, "check": email, "type": "email"},
            timeout=12
        )
        if r.status_code == 200:
            data = r.json()
            sources = data.get("sources", [])
            return {
                "email": email, "found": len(sources) > 0,
                "breach_count": len(sources),
                "breaches": [{"name": s.get("name"), "date": s.get("date"), "fields": s.get("fields", [])}
                              for s in sources[:10]]
            }
        return {"error": f"status_{r.status_code}", "found": False, "breach_count": 0, "breaches": []}
    except Exception as e:
        return {"error": str(e), "found": False, "breach_count": 0, "breaches": []}


def leakcheck_domain(domain: str) -> dict:
    domain = _normalize_domain(domain)
    api_key = os.getenv("LEAKCHECK_API_KEY", "")
    if not api_key:
        return {"error": "no_key", "domain": domain, "found": False,
                "total_exposed_accounts": 0, "unique_breaches": 0, "breach_sources": []}
    try:
        r = requests.get(
            "https://leakcheck.io/api/v2/query",
            params={"key": api_key, "check": domain, "type": "domain"},
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            sources = data.get("sources", [])
            found = data.get("found", 0)
            return {
                "domain": domain, "found": found > 0,
                "total_exposed_accounts": found,
                "breach_sources": [{"name": s.get("name", "Unknown"), "date": s.get("date", "N/A"),
                                     "unverified": s.get("unverified", False), "fields": s.get("fields", [])}
                                    for s in sources[:15]],
                "unique_breaches": len(sources),
            }
        return {"error": f"status_{r.status_code}", "domain": domain, "found": False,
                "total_exposed_accounts": 0, "unique_breaches": 0, "breach_sources": []}
    except Exception as e:
        return {"error": str(e), "domain": domain, "found": False,
                "total_exposed_accounts": 0, "unique_breaches": 0, "breach_sources": []}


# ─── CRT.SH SUBDOMAINS ────────────────────────────────────────
def crtsh_subdomains(domain: str) -> dict:
    domain = _normalize_domain(domain)
    empty = {"domain": domain, "total": 0, "sensitive": [], "normal": [], "certificate_records": 0}

    # Try multiple crt.sh endpoint formats — they change periodically
    endpoints = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
        f"https://crt.sh/?identity=%.{domain}&output=json",
    ]
    data = None
    for url in endpoints:
        try:
            r = requests.get(url, timeout=25, headers=_headers())
            if r.status_code == 200 and r.text.strip().startswith('['):
                data = r.json()
                if data:
                    break
        except Exception:
            continue

    # Fallback: OTX passive DNS (free, no key needed)
    if not data:
        otx_key = os.getenv("OTX_API_KEY", "")
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers=_headers({"X-OTX-API-KEY": otx_key} if otx_key else {}),
                timeout=15
            )
            if r.status_code == 200:
                passive = r.json().get("passive_dns", [])
                subdomains = set()
                for entry in passive:
                    host = entry.get("hostname", "")
                    if domain in host and not host.startswith("*"):
                        subdomains.add(host.lower())
                if subdomains:
                    return _classify_subdomains(domain, list(subdomains), cert_records=0)
        except Exception:
            pass

    # Fallback: VirusTotal subdomains (free 500/day, no key needed for basic)
    if not data:
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if vt_key:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
                    headers=_headers({"x-apikey": vt_key}),
                    timeout=15
                )
                if r.status_code == 200:
                    items = r.json().get("data", [])
                    subdomains = [item["id"] for item in items if "id" in item]
                    if subdomains:
                        return _classify_subdomains(domain, subdomains, cert_records=0)
            except Exception:
                pass

    if not data:
        return {**empty, "error": "crt.sh unavailable and no fallback API keys configured (OTX_API_KEY or VIRUSTOTAL_API_KEY)"}

    subdomains = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name and domain in name and not name.startswith("*"):
                subdomains.add(name)

    return _classify_subdomains(domain, list(subdomains), cert_records=len(data))


def _classify_subdomains(domain: str, subdomain_list: list, cert_records: int) -> dict:
    sensitive_keywords = [
        "admin", "mail", "vpn", "remote", "dev", "staging", "api",
        "portal", "ftp", "ssh", "login", "dashboard", "internal",
        "test", "beta", "secure", "owa", "webmail", "gitlab",
        "jenkins", "jira", "confluence", "backup", "db", "database",
        "panel", "cpanel", "plesk", "phpmyadmin", "upload", "git",
        "ci", "monitor", "grafana", "kibana", "elastic", "mgmt",
        "management", "prod", "production", "corp", "intranet",
    ]
    sensitive, normal = [], []
    for sub in sorted(set(subdomain_list)):
        prefix = sub.replace(f".{domain}", "").lower()
        if any(k in prefix for k in sensitive_keywords):
            sensitive.append(sub)
        else:
            normal.append(sub)
    return {
        "domain": domain,
        "total": len(subdomain_list),
        "sensitive": sensitive[:30],
        "normal": normal[:50],
        "certificate_records": cert_records,
    }


# ─── URLSCAN.IO ───────────────────────────────────────────────
def urlscan_domain(domain: str) -> dict:
    domain = _normalize_domain(domain)
    api_key = os.getenv("URLSCAN_API_KEY", "")
    headers = _headers({"API-Key": api_key} if api_key else {})
    empty = {"domain": domain, "scans_found": 0, "technologies": [], "recent_pages": [], "known_ips": []}
    try:
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 10},
            headers=headers,
            timeout=15
        )
        if r.status_code == 429:
            return {**empty, "error": "URLScan rate limited — add URLSCAN_API_KEY to .env"}
        if r.status_code != 200:
            return {**empty, "error": f"URLScan status {r.status_code}"}

        results = r.json().get("results", [])
        if not results:
            return {**empty}

        pages, ip_addresses = [], set()
        for scan in results[:8]:
            page = scan.get("page", {})
            if page.get("ip"):
                ip_addresses.add(page["ip"])
            pages.append({
                "url": page.get("url", ""),
                "ip": page.get("ip", ""),
                "server": page.get("server", ""),
                "status": page.get("status", ""),
                "country": page.get("country", ""),
                "scan_date": scan.get("task", {}).get("time", "")[:10],
            })

        # Tech stack — check all known response locations
        technologies = []
        for scan in results[:3]:
            wappa = scan.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])
            tech_list = scan.get("page", {}).get("tech", [])
            tags = scan.get("verdicts", {}).get("overall", {}).get("tags", [])
            if wappa:
                for t in wappa:
                    name = t.get("app", t.get("name", ""))
                    if name and not any(x["name"] == name for x in technologies):
                        technologies.append({"name": name, "categories": t.get("categories", [])})
            elif tech_list:
                for t in tech_list:
                    name = t.get("name", "")
                    if name and not any(x["name"] == name for x in technologies):
                        technologies.append({"name": name, "categories": t.get("categories", [t.get("category", "")])})
            elif tags:
                for tag in tags:
                    if not any(x["name"] == tag for x in technologies):
                        technologies.append({"name": tag, "categories": []})
            if technologies:
                break

        return {
            "domain": domain,
            "scans_found": len(results),
            "total_results": r.json().get("total", 0),
            "technologies": technologies[:10],
            "recent_pages": pages,
            "known_ips": list(ip_addresses)[:8],
        }
    except Exception as e:
        return {**empty, "error": str(e)}


# ─── INTELX PHONEBOOK ────────────────────────────────────────
def intelx_phonebook(domain: str) -> dict:
    domain = _normalize_domain(domain)
    api_key = os.getenv("INTELX_API_KEY", "")
    empty = {"domain": domain, "emails_found": [], "related_urls": [],
             "related_domains": [], "total_selectors": 0, "email_count": 0}

    if not api_key:
        return {**empty, "error": "no_key"}

    headers = _headers({"x-key": api_key, "Content-Type": "application/json"})
    base_url = "https://2.intelx.io"
    try:
        r = requests.post(
            f"{base_url}/phonebook/search",
            json={"term": domain, "maxresults": 200, "media": 0, "target": 0, "terminate": []},
            headers=headers, timeout=15
        )
        if r.status_code in (401, 403):
            return {**empty, "error": f"IntelX API key invalid or expired ({r.status_code})"}
        if r.status_code != 200:
            return {**empty, "error": f"IntelX search status {r.status_code}"}

        search_id = r.json().get("id", "")
        if not search_id:
            return empty

        time.sleep(2)
        r2 = requests.get(
            f"{base_url}/phonebook/search/result",
            params={"id": search_id, "limit": 200, "offset": 0},
            headers=headers, timeout=15
        )
        if r2.status_code != 200:
            return {**empty, "error": f"IntelX result status {r2.status_code}"}

        selectors = r2.json().get("selectors", [])
        emails, urls, domains_found = [], [], []
        for item in selectors:
            val = item.get("selectorvalue", "").strip()
            if not val:
                continue
            if "@" in val and domain in val.lower():
                emails.append(val)
            elif val.startswith("http") and domain in val.lower():
                urls.append(val)
            elif domain in val.lower() and "@" not in val and not val.startswith("http"):
                domains_found.append(val)

        unique_emails = list(dict.fromkeys(emails))
        return {
            "domain": domain,
            "emails_found": unique_emails[:30],
            "related_urls": list(dict.fromkeys(urls))[:15],
            "related_domains": list(dict.fromkeys(domains_found))[:15],
            "total_selectors": len(selectors),
            "email_count": len(unique_emails),
        }
    except Exception as e:
        return {**empty, "error": str(e)}


# ─── DNS RECON ────────────────────────────────────────────────
def dns_recon(domain: str) -> dict:
    domain = _normalize_domain(domain)
    records = {"mx": [], "a": [], "txt": [], "ns": [],
               "resolved_ip": "N/A", "email_provider": "Unknown / Self-hosted"}

    if _DNS_AVAILABLE and _dns_resolver is not None:
        try:
            resolver = _dns_resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            for rtype, key, transform in [
                ("MX",  "mx",  lambda r: str(r.exchange).rstrip('.')),
                ("A",   "a",   lambda r: str(r)),
                ("TXT", "txt", lambda r: str(r)),
                ("NS",  "ns",  lambda r: str(r.target).rstrip('.')),
            ]:
                try:
                    ans = resolver.resolve(domain, rtype)
                    records[key] = [transform(x) for x in ans][:5]
                except Exception:
                    pass
            if records["a"]:
                records["resolved_ip"] = records["a"][0]
        except Exception:
            pass

    # Socket fallback for IP
    if records["resolved_ip"] == "N/A":
        try:
            records["resolved_ip"] = socket.gethostbyname(domain)
        except Exception:
            pass

    # HackerTarget fallback if dnspython unavailable
    if not records["a"]:
        try:
            r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}",
                             timeout=10, headers=_headers())
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.strip().split("\n"):
                    if " MX " in line and not records["mx"]:
                        records["mx"].append(line.split()[-1])
                    elif " A " in line and not records["a"]:
                        records["a"].append(line.split()[-1])
                    elif " TXT " in line and not records["txt"]:
                        records["txt"].append(line.strip())
        except Exception:
            pass

    # Email provider detection
    mx_str = " ".join(records.get("mx", [])).lower()
    if "google" in mx_str or "aspmx" in mx_str or "googlemail" in mx_str:
        records["email_provider"] = "Google Workspace"
    elif "outlook" in mx_str or "protection.outlook" in mx_str or "microsoft" in mx_str:
        records["email_provider"] = "Microsoft 365"
    elif "proofpoint" in mx_str or "pphosted" in mx_str:
        records["email_provider"] = "Proofpoint"
    elif "mimecast" in mx_str:
        records["email_provider"] = "Mimecast"
    elif "mailgun" in mx_str:
        records["email_provider"] = "Mailgun"
    elif "sendgrid" in mx_str:
        records["email_provider"] = "SendGrid"
    elif "amazonses" in mx_str or "amazonaws" in mx_str:
        records["email_provider"] = "Amazon SES"
    elif "barracuda" in mx_str:
        records["email_provider"] = "Barracuda"
    elif records["mx"]:
        records["email_provider"] = "Self-hosted / Custom MTA"
    else:
        records["email_provider"] = "Unknown / Self-hosted"

    return records


# ─── DIGITAL RISK SCORE ───────────────────────────────────────
def compute_risk_score(leak: dict, subs: dict, hunter: dict, intelx: dict, urlscan: dict) -> dict:
    score = 0
    factors = []

    exposed = leak.get("total_exposed_accounts", 0)
    breaches = leak.get("unique_breaches", 0)
    if exposed > 100:
        score += 45; factors.append(f"CRITICAL: {exposed} accounts in {breaches} breach databases")
    elif exposed > 50:
        score += 35; factors.append(f"HIGH: {exposed} accounts in {breaches} breaches")
    elif exposed > 10:
        score += 25; factors.append(f"MEDIUM: {exposed} accounts in {breaches} breaches")
    elif exposed > 0:
        score += 15; factors.append(f"{exposed} accounts in {breaches} breaches")

    sensitive_count = len(subs.get("sensitive", []))
    total_subs = subs.get("total", 0)
    if sensitive_count > 8:
        score += 20; factors.append(f"HIGH: {sensitive_count} sensitive subdomains exposed")
    elif sensitive_count > 3:
        score += 12; factors.append(f"MEDIUM: {sensitive_count} sensitive subdomains")
    elif sensitive_count > 0:
        score += 6; factors.append(f"{sensitive_count} potentially sensitive subdomains")
    elif total_subs > 20:
        score += 4; factors.append(f"Large attack surface: {total_subs} subdomains")

    intelx_emails = intelx.get("email_count", 0)
    if intelx_emails > 15:
        score += 15; factors.append(f"HIGH: {intelx_emails} employee emails in paste/leak databases")
    elif intelx_emails > 5:
        score += 10; factors.append(f"MEDIUM: {intelx_emails} emails in IntelX")
    elif intelx_emails > 0:
        score += 5; factors.append(f"{intelx_emails} email mentions in indexed leak sources")

    scans = urlscan.get("scans_found", 0)
    techs = urlscan.get("technologies", [])
    if scans > 0 and techs:
        score += 10; factors.append(f"Tech stack fingerprinted: {', '.join([t['name'] for t in techs[:3]])}")
    elif scans > 0:
        score += 5; factors.append(f"Web presence confirmed — {scans} URLScan records")

    if not factors:
        factors.append("No significant exposure detected across scanned sources")

    score = min(score, 100)
    if score >= 70:
        level, summary = "CRITICAL", "Severe digital exposure. Immediate remediation required."
    elif score >= 45:
        level, summary = "HIGH", "Significant breach history and discoverable employee data present substantial risk."
    elif score >= 20:
        level, summary = "MEDIUM", "Some breach history and discoverable assets require attention."
    else:
        level, summary = "LOW", "Limited publicly known exposure detected. Maintain current security hygiene."

    return {"score": score, "level": level, "summary": summary, "factors": factors}


# ─── HUNTER.IO EMAIL FINDER ──────────────────────────────────
def hunter_email_lookup(email: str) -> dict:
    """Verify a specific email + find breach context via Hunter.io"""
    api_key = os.getenv("HUNTER_API_KEY", "")
    if not api_key:
        return {"error": "no_key", "found": False, "breach_count": 0, "breaches": []}
    try:
        r = requests.get(
            "https://api.hunter.io/v2/email-verifier",
            params={"email": email, "api_key": api_key},
            timeout=12
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            status = data.get("status", "unknown")
            return {
                "email": email,
                "found": status in ("valid", "accept_all"),
                "status": status,
                "score": data.get("score", 0),
                "disposable": data.get("disposable", False),
                "gibberish": data.get("gibberish", False),
                "mx_records": data.get("mx_records", False),
                "smtp_check": data.get("smtp_server", False),
                "breach_count": 0,  # Hunter doesn't do breach lookup
                "breaches": [],
            }
        return {"error": f"Hunter status {r.status_code}", "found": False, "breach_count": 0, "breaches": []}
    except Exception as e:
        return {"error": str(e), "found": False, "breach_count": 0, "breaches": []}


def hunter_domain_search(domain: str) -> dict:
    """Find employee emails for a domain using Hunter.io"""
    domain = _normalize_domain(domain)
    api_key = os.getenv("HUNTER_API_KEY", "")
    if not api_key:
        return {"error": "no_key", "domain": domain, "total_found": 0, "emails": [],
                "org_name": "", "email_pattern": ""}
    try:
        r = requests.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "limit": 20, "api_key": api_key},
            timeout=15
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            emails = []
            for e in data.get("emails", []):
                emails.append({
                    "email": e.get("value", ""),
                    "confidence": e.get("confidence", 0),
                    "name": f"{e.get('first_name','')} {e.get('last_name','')}".strip(),
                    "position": e.get("position", ""),
                    "department": e.get("department", ""),
                    "linkedin": e.get("linkedin", ""),
                })
            return {
                "domain": domain,
                "total_found": data.get("meta", {}).get("total", len(emails)),
                "emails": emails[:15],
                "org_name": data.get("organization", ""),
                "email_pattern": data.get("pattern", ""),
            }
        return {"error": f"Hunter status {r.status_code}", "domain": domain,
                "total_found": 0, "emails": [], "org_name": "", "email_pattern": ""}
    except Exception as e:
        return {"error": str(e), "domain": domain, "total_found": 0,
                "emails": [], "org_name": "", "email_pattern": ""}
