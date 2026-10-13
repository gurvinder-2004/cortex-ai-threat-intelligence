import requests
import os
from dotenv import load_dotenv

load_dotenv()

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

def otx_lookup(target: str, target_type: str = "ip") -> dict:
    """
    Looks up threat intelligence from OTX AlienVault
    target_type: 'ip', 'domain', or 'hostname'
    """
    api_key = os.getenv("OTX_API_KEY")
    headers = {"X-OTX-API-KEY": api_key}

    try:
        # General info
        if target_type == "ip":
            url = f"{OTX_BASE_URL}/indicators/IPv4/{target}/general"
        else:
            url = f"{OTX_BASE_URL}/indicators/domain/{target}/general"

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return {"error": f"OTX request failed: {response.status_code}"}

        data = response.json()

        # Extract pulse info (threat reports mentioning this target)
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        pulse_summary = []
        for pulse in pulses[:5]:  # top 5 pulses
            pulse_summary.append({
                "name": pulse.get("name"),
                "description": pulse.get("description", "")[:200],
                "author": pulse.get("author_name"),
                "created": pulse.get("created"),
                "tags": pulse.get("tags", [])[:5],
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": [a.get("display_name") for a in pulse.get("attack_ids", [])][:5]
            })

        return {
            "target": target,
            "pulse_count": pulse_info.get("count", 0),
            "reputation": data.get("reputation", 0),
            "threat_score": data.get("threat_score", 0) if "threat_score" in data else "N/A",
            "country": data.get("country_name", "N/A"),
            "top_pulses": pulse_summary
        }

    except Exception as e:
        return {"error": str(e)}