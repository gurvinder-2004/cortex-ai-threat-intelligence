import requests
import socket

def whois_lookup(target: str) -> dict:
    try:
        # Primary: ip-api.com (no key needed, generous limits)
        response = requests.get(f"http://ip-api.com/json/{target}")
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": target,
                    "city": data.get("city", "N/A"),
                    "region": data.get("regionName", "N/A"),
                    "country": data.get("country", "N/A"),
                    "org": data.get("org", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "timezone": data.get("timezone", "N/A"),
                    "asn": data.get("as", "N/A"),
                    "lat": data.get("lat", "N/A"),
                    "lon": data.get("lon", "N/A")
                }
        return {"error": f"Status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}