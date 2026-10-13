import re

def extract_iocs_regex(text: str) -> dict:
    """Fast regex-based IOC extraction"""
    patterns = {
        "ipv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "domains": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|onion)\b',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
        "cves": r'CVE-\d{4}-\d{4,7}',
        "emails": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "urls": r'https?://[^\s<>"{}|\\^`\[\]]+'
    }

    extracted = {}
    for ioc_type, pattern in patterns.items():
        matches = list(set(re.findall(pattern, text)))
        if matches:
            extracted[ioc_type] = matches[:10]

    return extracted