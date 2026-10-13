from tools.breach_tools import (
    leakcheck_domain, crtsh_subdomains, urlscan_domain,
    intelx_phonebook, dns_recon, compute_risk_score
)


def run_breach_radar(domain: str) -> dict:
    """Legacy CLI entry point — dashboard uses tools directly now."""
    from tools.breach_tools import _normalize_domain
    domain = _normalize_domain(domain)
    print(f"\n[BREACH RADAR] Scanning: {domain}")
    r = {}

    print("[*] LeakCheck — breach database scan...")
    r["leakcheck"] = leakcheck_domain(domain)

    print("[*] crt.sh — subdomain enumeration...")
    r["subdomains"] = crtsh_subdomains(domain)

    print("[*] URLScan.io — web fingerprinting...")
    r["urlscan"] = urlscan_domain(domain)

    print("[*] IntelX — paste/leak site search...")
    r["intelx"] = intelx_phonebook(domain)

    print("[*] DNS recon...")
    r["dns"] = dns_recon(domain)

    print("[*] Computing Digital Risk Score...")
    r["hunter"] = {"total_found": 0, "emails": []}  # Hunter removed
    r["risk"] = compute_risk_score(
        r["leakcheck"], r["subdomains"],
        r["hunter"], r["intelx"], r["urlscan"]
    )

    print(f"[BREACH RADAR] Done. Score: {r['risk']['score']}/100 — {r['risk']['level']}")
    return r
