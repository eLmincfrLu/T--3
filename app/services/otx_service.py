"""AlienVault OTX (Open Threat Exchange) integration — a broad, VirusTotal-
style aggregator that supplements our other narrow single-purpose sources.
Unlike AbuseIPDB (IP-only) or Safe Browsing/URLhaus (URL/domain-only), OTX
covers IPs, domains, and URLs alike. Same normalized-signal contract as
the other *_service.py modules.
"""

import os
from urllib.parse import quote

import requests

OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
REQUEST_TIMEOUT = 15
# A single pulse can just be background/context (e.g. a research writeup
# that mentions this IP incidentally), so we require a few before treating
# the target as flagged — reduces false positives from one-off mentions.
MALICIOUS_PULSE_THRESHOLD = 3

# Maps our internal target_type to OTX's indicator type segment.
OTX_TYPE_MAP = {"ip": "IPv4", "domain": "domain", "url": "url"}


def _empty_signal(reason: str = "not_applicable") -> dict:
    return {
        "source": "AlienVault OTX",
        "ran": False,
        "available": False,
        "malicious": False,
        "detail": None,
        "reason": reason,
    }


def check_indicator(target: str, target_type: str) -> dict:
    """Looks up an IP, domain, or URL in AlienVault OTX's community threat
    database. Never raises — any failure (missing key, network error,
    non-200, unsupported type) degrades gracefully to an 'unavailable'
    signal so this source's outage never blocks the overall analysis."""
    otx_type = OTX_TYPE_MAP.get(target_type)
    if not otx_type:
        return _empty_signal("not_applicable")

    api_key = os.getenv("OTX_API_KEY", "").strip()
    if not api_key:
        return _empty_signal("missing_api_key")

    encoded_target = quote(target, safe="")
    url = f"{OTX_BASE_URL}/{otx_type}/{encoded_target}/general"

    try:
        response = requests.get(
            url,
            headers={"X-OTX-API-KEY": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if not response.ok:
            return _empty_signal(f"http_{response.status_code}")
        data = response.json()
    except (requests.RequestException, ValueError):
        return _empty_signal("request_failed")

    pulse_count = int((data.get("pulse_info") or {}).get("count", 0) or 0)
    is_malicious = pulse_count >= MALICIOUS_PULSE_THRESHOLD

    return {
        "source": "AlienVault OTX",
        "ran": True,
        "available": True,
        "malicious": is_malicious,
        "pulse_count": pulse_count,
        "detail": f"Referenced in {pulse_count} threat report(s)" if pulse_count
        else "No threat reports found",
        "reason": None,
    }