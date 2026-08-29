"""AZ Threat Radar local IOC feed — a curated, in-house list of confirmed
phishing/malware domains and IPs (see app/data/local_ioc_store.py).

Unlike the other *_service.py modules this needs no API key and no
network call, so it always runs and answers instantly. Same normalized-
signal contract as abuseipdb_service.py / otx_service.py / etc.
"""

from app.data.local_ioc_store import lookup

SOURCE_NAME = "AZ Threat Radar Local Intel"


def check_indicator(target: str, target_type: str) -> dict:
    """Checks a target against the local IOC feed. Applies to ip, domain,
    and url target types. Never raises and never returns 'unavailable' —
    the local feed is always loaded in-process."""
    is_match = lookup(target, target_type)
    return {
        "source": SOURCE_NAME,
        "ran": True,
        "available": True,
        "malicious": is_match,
        "detail": "Matched known-malicious indicator in local feed"
        if is_match
        else "No match in local feed",
        "reason": None,
    }