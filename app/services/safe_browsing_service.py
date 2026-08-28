"""Google Safe Browsing integration — supplements VirusTotal for URL and
domain analysis. Same normalized-signal contract as abuseipdb_service.py."""

import os

import requests

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
REQUEST_TIMEOUT = 15

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def _empty_signal(reason: str = "not_applicable") -> dict:
    return {
        "source": "Google Safe Browsing",
        "ran": False,
        "available": False,
        "malicious": False,
        "detail": None,
        "reason": reason,
    }


def check_url(target: str, target_type: str) -> dict:
    """Looks up a URL or domain against Google's Safe Browsing threat lists.
    For domains, checks the bare hostname as an https:// URL, since Safe
    Browsing matches on URL patterns. Never raises — see abuseipdb_service
    for the fail-safe rationale."""
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return _empty_signal("missing_api_key")

    lookup_url = target if target_type == "url" else f"https://{target}"

    body = {
        "client": {"clientId": "az-threat-radar", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": lookup_url}],
        },
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": api_key},
            json=body,
            timeout=REQUEST_TIMEOUT,
        )
        if not response.ok:
            return _empty_signal(f"http_{response.status_code}")
        data = response.json()
    except (requests.RequestException, ValueError):
        return _empty_signal("request_failed")

    matches = data.get("matches") or []
    if not matches:
        return {
            "source": "Google Safe Browsing",
            "ran": True,
            "available": True,
            "malicious": False,
            "threat_types": [],
            "detail": "No threats found",
            "reason": None,
        }

    threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    return {
        "source": "Google Safe Browsing",
        "ran": True,
        "available": True,
        "malicious": True,
        "threat_types": threat_types,
        "detail": f"Flagged: {', '.join(threat_types)}",
        "reason": None,
    }