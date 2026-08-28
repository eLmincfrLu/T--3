"""AbuseIPDB integration — supplements VirusTotal for IP-address analysis.

Returns a normalized "signal" dict so threat_service.py can merge results
from multiple sources without caring about each provider's raw response
shape. A signal always has: source, ran, available, malicious, detail.
"""

import os

import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 15
MALICIOUS_CONFIDENCE_THRESHOLD = 50  # abuseConfidenceScore >= this counts as flagged


def _empty_signal(reason: str = "not_applicable") -> dict:
    return {
        "source": "AbuseIPDB",
        "ran": False,
        "available": False,
        "malicious": False,
        "detail": None,
        "reason": reason,
    }


def check_ip(ip: str) -> dict:
    """Looks up an IP address in AbuseIPDB. Only meaningful for target_type
    'ip' — callers should not invoke this for domains/URLs. Never raises:
    any failure (missing key, network error, non-200) degrades gracefully
    to an 'unavailable' signal so one provider's outage never blocks the
    overall analysis."""
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return _empty_signal("missing_api_key")

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )
        if not response.ok:
            return _empty_signal(f"http_{response.status_code}")
        data = response.json().get("data") or {}
    except (requests.RequestException, ValueError):
        return _empty_signal("request_failed")

    confidence = int(data.get("abuseConfidenceScore", 0) or 0)
    total_reports = int(data.get("totalReports", 0) or 0)
    is_malicious = confidence >= MALICIOUS_CONFIDENCE_THRESHOLD

    return {
        "source": "AbuseIPDB",
        "ran": True,
        "available": True,
        "malicious": is_malicious,
        "confidence": confidence,
        "country": data.get("countryCode") or None,
        "isp": data.get("isp") or None,
        "total_reports": total_reports,
        "detail": f"{confidence}% abuse confidence ({total_reports} reports)",
        "reason": None,
    }