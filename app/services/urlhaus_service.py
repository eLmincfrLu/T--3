"""URLhaus (abuse.ch) integration — supplements VirusTotal for URL and
domain analysis with a community-sourced malware-distribution feed.
Same normalized-signal contract as abuseipdb_service.py.

Note: abuse.ch now requires an Auth-Key for all API access (their
"community API" tier is still free — see https://auth.abuse.ch/)."""

import os

import requests

URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
REQUEST_TIMEOUT = 15


def _empty_signal(reason: str = "not_applicable") -> dict:
    return {
        "source": "URLhaus",
        "ran": False,
        "available": False,
        "malicious": False,
        "detail": None,
        "reason": reason,
    }


def _auth_key() -> str:
    return os.getenv("URLHAUS_AUTH_KEY", "").strip()


def check_target(target: str, target_type: str) -> dict:
    """Looks up a URL or domain in URLhaus. For URLs, queries the exact URL
    endpoint; for domains, queries the host endpoint (which also accepts
    IPs, though we route IPs through AbuseIPDB instead). Never raises."""
    api_key = _auth_key()
    if not api_key:
        return _empty_signal("missing_api_key")

    headers = {"Auth-Key": api_key}

    if target_type == "url":
        endpoint = URLHAUS_URL_ENDPOINT
        post_data = {"url": target}
    elif target_type == "domain":
        endpoint = URLHAUS_HOST_ENDPOINT
        post_data = {"host": target}
    else:
        return _empty_signal("not_applicable")

    try:
        response = requests.post(endpoint, headers=headers, data=post_data, timeout=REQUEST_TIMEOUT)
        if not response.ok:
            return _empty_signal(f"http_{response.status_code}")
        data = response.json()
    except (requests.RequestException, ValueError):
        return _empty_signal("request_failed")

    status = data.get("query_status")
    if status != "ok":
        # "no_results" (not listed) is the common, expected "clean" case.
        return {
            "source": "URLhaus",
            "ran": True,
            "available": True,
            "malicious": False,
            "detail": "Not listed" if status == "no_results" else f"Query status: {status}",
            "reason": None,
        }

    if target_type == "url":
        threat = data.get("threat") or "malware_download"
        url_status = data.get("url_status", "unknown")
        return {
            "source": "URLhaus",
            "ran": True,
            "available": True,
            "malicious": True,
            "detail": f"Listed as {threat} ({url_status})",
            "reason": None,
        }

    # host endpoint: "urls" is a list of malicious URLs seen on this host
    urls = data.get("urls") or []
    online_count = sum(1 for u in urls if u.get("url_status") == "online")
    if not urls:
        return {
            "source": "URLhaus",
            "ran": True,
            "available": True,
            "malicious": False,
            "detail": "Not listed",
            "reason": None,
        }
    return {
        "source": "URLhaus",
        "ran": True,
        "available": True,
        "malicious": True,
        "detail": f"{len(urls)} malicious URL(s) seen on this host ({online_count} still online)",
        "reason": None,
    }