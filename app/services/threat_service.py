from datetime import datetime, timezone

from app.services.abuseipdb_service import check_ip as abuseipdb_check
from app.services.otx_service import check_indicator as otx_check
from app.services.risk_engine import compute_risk
from app.services.safe_browsing_service import check_url as safe_browsing_check
from app.services.urlhaus_service import check_target as urlhaus_check
from app.services.virustotal_service import fetch_threat_intel

# How much each corroborating source adds to the risk score on top of
# VirusTotal's own base score + category weights. Kept modest per-source
# so that no single extra signal can single-handedly flip a result, but
# several sources agreeing pushes the score up meaningfully (consensus).
ABUSEIPDB_WEIGHT = 20
SAFE_BROWSING_WEIGHT = 25
URLHAUS_WEIGHT = 25
OTX_WEIGHT = 15


def _category_weights(reputation: dict) -> dict[str, int]:
    weights = {
        "Phishing": 0,
        "Malware Hosting": 0,
        "Botnet Activity": 0,
        "Spam": 0,
        "Suspicious Network": 0,
        "Abuse Reports": 0,
        "Threat Intelligence": 0,
    }
    if reputation["phishing_detection"] == "Detected":
        weights["Phishing"] = 25
    if reputation["malware_detection"] == "Detected":
        weights["Malware Hosting"] = 30
    if reputation["spam_detection"] == "Detected":
        weights["Spam"] = 10
    if reputation["blacklist_status"] == "Listed":
        weights["Suspicious Network"] = 15

    malicious = int(reputation.get("vt_malicious_count", 0))
    suspicious = int(reputation.get("vt_suspicious_count", 0))
    if malicious >= 10 or suspicious >= 5:
        weights["Botnet Activity"] = 20
    return weights


def _base_score(reputation: dict) -> int:
    malicious = int(reputation.get("vt_malicious_count", 0))
    suspicious = int(reputation.get("vt_suspicious_count", 0))
    return min(100, malicious * 8 + suspicious * 4)


def _gather_extra_sources(target: str, target_type: str) -> list[dict]:
    """Calls the extra threat-intel sources relevant to this target_type.
    Each call is isolated: a failure or missing key in one source never
    prevents the others from running or blocks the overall analysis."""
    signals = []
    if target_type == "ip":
        signals.append(abuseipdb_check(target))
    if target_type in ("url", "domain"):
        signals.append(safe_browsing_check(target, target_type))
        signals.append(urlhaus_check(target, target_type))
    signals.append(otx_check(target, target_type))
    return signals


def _apply_extra_sources(weights: dict[str, int], signals: list[dict]) -> None:
    """Folds each corroborating source's verdict into the category weights
    in place. A source only contributes when it actually ran and flagged
    the target — sources that were skipped (no API key, wrong target
    type) or came back clean contribute nothing."""
    for signal in signals:
        if not signal.get("available") or not signal.get("malicious"):
            continue
        if signal["source"] == "AbuseIPDB":
            weights["Abuse Reports"] = max(weights.get("Abuse Reports", 0), ABUSEIPDB_WEIGHT)
        elif signal["source"] == "Google Safe Browsing":
            threat_types = signal.get("threat_types") or []
            if "SOCIAL_ENGINEERING" in threat_types:
                weights["Phishing"] = max(weights.get("Phishing", 0), SAFE_BROWSING_WEIGHT)
            else:
                weights["Malware Hosting"] = max(weights.get("Malware Hosting", 0), SAFE_BROWSING_WEIGHT)
        elif signal["source"] == "URLhaus":
            weights["Malware Hosting"] = max(weights.get("Malware Hosting", 0), URLHAUS_WEIGHT)
        elif signal["source"] == "AlienVault OTX":
            weights["Threat Intelligence"] = max(weights.get("Threat Intelligence", 0), OTX_WEIGHT)


def _fill_network_fallback(network: dict, signals: list[dict]) -> None:
    """VirusTotal sometimes returns 'Unknown' for country/ISP (e.g. for
    freshly-seen IPs it hasn't fully profiled). When that happens, fall
    back to AbuseIPDB's data for the same fields — it's IP-only, so this
    only applies when we actually ran an AbuseIPDB lookup. Mutates network
    in place; does nothing if AbuseIPDB didn't run or has no usable data."""
    abuseipdb_signal = next(
        (s for s in signals if s.get("source") == "AbuseIPDB" and s.get("available")), None
    )
    if not abuseipdb_signal:
        return
    if network.get("country") in (None, "", "Unknown") and abuseipdb_signal.get("country"):
        network["country"] = abuseipdb_signal["country"]
    if network.get("isp") in (None, "", "Unknown") and abuseipdb_signal.get("isp"):
        network["isp"] = abuseipdb_signal["isp"]


def analyze_target(target: str, target_type: str) -> dict:
    intel = fetch_threat_intel(target, target_type)
    reputation = intel["reputation"]
    network = intel["network"]
    whois = intel["whois"]
    weights = _category_weights(reputation)
    base = _base_score(reputation)

    extra_signals = _gather_extra_sources(target, target_type)
    _apply_extra_sources(weights, extra_signals)
    _fill_network_fallback(network, extra_signals)

    risk = compute_risk(base, weights)
    threats = risk.categories if risk.categories else (["None"] if risk.status == "SAFE" else [])

    sources = [{"source": "VirusTotal", "ran": True, "available": True,
                "malicious": bool(risk.categories), "detail": reputation["virustotal_status"]}]
    sources.extend(extra_signals)

    return {
        "target": target,
        "type": target_type,
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk.score,
        "status": risk.status,
        "recommendation": risk.recommendation,
        "threat_categories": threats,
        "country": network["country"],
        "isp": network["isp"],
        "asn": network["asn"],
        "hostname": network["hostname"],
        "whois": whois,
        "reputation": reputation,
        "sources": sources,
    }