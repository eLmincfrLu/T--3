"""In-memory store for the AZ Threat Radar local IOC (Indicator of
Compromise) feed — a curated list of confirmed-malicious domains and IPs
observed in phishing/malware campaigns.

Loaded once at import time from the plain-text files in this directory
(one indicator per line, '#' comments allowed). Team members can extend
the feed by editing iocs_domains.txt / iocs_ips.txt directly — no code
change needed — and restarting the app.
"""

import os
from urllib.parse import urlparse

_DATA_DIR = os.path.dirname(os.path.abspath(__file__))
_DOMAINS_FILE = os.path.join(_DATA_DIR, "iocs_domains.txt")
_IPS_FILE = os.path.join(_DATA_DIR, "iocs_ips.txt")


def _load(path: str) -> frozenset[str]:
    if not os.path.exists(path):
        return frozenset()
    with open(path, "r", encoding="utf-8") as f:
        return frozenset(
            line.strip().lower()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        )


KNOWN_DOMAINS = _load(_DOMAINS_FILE)
KNOWN_IPS = _load(_IPS_FILE)


def _extract_hostname(target: str, target_type: str) -> str:
    value = (target or "").strip().lower()
    if target_type == "url" or "://" in value:
        value = urlparse(value if "://" in value else f"//{value}").hostname or value
    return value.removeprefix("www.")


def lookup(target: str, target_type: str) -> bool:
    """Returns True if the target (or, for URLs, its hostname) matches a
    known-malicious indicator in the local feed."""
    if target_type == "ip":
        return target.strip() in KNOWN_IPS
    hostname = _extract_hostname(target, target_type)
    return hostname in KNOWN_DOMAINS


def feed_size() -> dict:
    return {"domains": len(KNOWN_DOMAINS), "ips": len(KNOWN_IPS)}