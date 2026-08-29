"""Optional live enrichment for the CVE watchlist: cross-checks our static
CVE_LIST against CISA's public Known Exploited Vulnerabilities (KEV)
catalog to attach real 'dateAdded' / 'dueDate' fields. No API key needed.

Fail-safe by design: if CISA is unreachable, slow, or returns something
unexpected, we silently fall back to the static data with no due dates
shown — the watchlist page must always render, live enrichment is a
bonus, not a dependency.
"""

import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 8


def fetch_kev_dates() -> dict[str, dict]:
    """Returns {cve_id: {"date_added": str, "due_date": str}} for whichever
    CVEs CISA's live feed responds with. Returns {} on any failure."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
        if not response.ok:
            return {}
        data = response.json()
    except (requests.RequestException, ValueError):
        return {}

    vulnerabilities = data.get("vulnerabilities") or []
    return {
        v["cveID"]: {"date_added": v.get("dateAdded"), "due_date": v.get("dueDate")}
        for v in vulnerabilities
        if v.get("cveID")
    }


def enrich_with_kev_dates(cve_list: list[dict]) -> list[dict]:
    """Returns a new list of CVE dicts with 'date_added'/'due_date' filled
    in where CISA's live feed has them. Never mutates the original static
    list; never raises."""
    kev_dates = fetch_kev_dates()
    enriched = []
    for cve in cve_list:
        merged = dict(cve)
        live = kev_dates.get(cve["id"])
        merged["date_added"] = live["date_added"] if live else None
        merged["due_date"] = live["due_date"] if live else None
        enriched.append(merged)
    return enriched