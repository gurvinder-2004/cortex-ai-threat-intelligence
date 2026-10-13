import os
import requests
from dotenv import load_dotenv
load_dotenv()


def shodan_lookup(ip: str) -> dict:
    """IP intelligence — tries paid Shodan key first, falls back to free InternetDB"""

    # Try paid Shodan API if key is present
    api_key = os.getenv("SHODAN_API_KEY", "")
    if api_key:
        try:
            import shodan
            api = shodan.Shodan(api_key)
            result = api.host(ip)
            return {
                "ip": ip,
                "org": result.get("org", "N/A"),
                "country": result.get("country_name", "N/A"),
                "city": result.get("city", "N/A"),
                "open_ports": result.get("ports", []),
                "hostnames": result.get("hostnames", []),
                "vulns": list(result.get("vulns", {}).keys()),
                "tags": result.get("tags", []),
                "source": "shodan_api",
            }
        except Exception as e:
            err = str(e)
            # If it's a plan restriction, fall through to InternetDB
            if "403" not in err and "upgrade" not in err.lower() and "plan" not in err.lower():
                return {"error": err, "ip": ip}

    # Free fallback: Shodan InternetDB (no key needed, works for all IPs)
    try:
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "ip": ip,
                "org": "N/A",
                "country": "N/A",
                "city": "N/A",
                "open_ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", []),
                "cpes": data.get("cpes", []),
                "source": "internetdb_free",
            }
        if r.status_code == 404:
            return {
                "ip": ip, "org": "N/A", "country": "N/A", "city": "N/A",
                "open_ports": [], "hostnames": [], "vulns": [], "tags": [],
                "note": "No Shodan data for this IP",
                "source": "internetdb_free",
            }
        return {"error": f"Shodan InternetDB status {r.status_code}", "ip": ip}
    except Exception as e:
        return {"error": str(e), "ip": ip}
