from flask import Blueprint, render_template
from flask_login import login_required

from app.data.cve_watchlist import CVE_LIST, unique_products
from app.data.threat_actors import get_actor
from app.services.cve_service import enrich_with_kev_dates

cve_bp = Blueprint("cve_watchlist", __name__)


@cve_bp.route("/cve-watchlist")
@login_required
def index():
    cves = enrich_with_kev_dates(CVE_LIST)
    cves_sorted = sorted(cves, key=lambda c: c["cvss"], reverse=True)
    for cve in cves_sorted:
        actor = get_actor(cve["actor_id"])
        cve["actor_name"] = actor["name"] if actor else None
    critical_count = sum(1 for c in cves_sorted if c["severity"] == "critical")
    kev_count = sum(1 for c in cves_sorted if c["kev"])
    actors_covered = len({c["actor_id"] for c in cves_sorted if c["actor_id"]})
    return render_template(
        "cve_watchlist.html",
        cves=cves_sorted,
        products=unique_products(),
        critical_count=critical_count,
        kev_count=kev_count,
        actors_covered=actors_covered,
    )