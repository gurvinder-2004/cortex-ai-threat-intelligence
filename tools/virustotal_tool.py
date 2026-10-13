import requests
import os
from dotenv import load_dotenv

load_dotenv()

def virustotal_lookup(target: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    headers = {"x-apikey": api_key}

    # works for both IP and domain
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        return {
            "target": target,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": data.get("reputation", 0),
            "tags": data.get("tags", []),
            "country": data.get("country", "N/A")
        }
    return {"error": f"Status {response.status_code}"}