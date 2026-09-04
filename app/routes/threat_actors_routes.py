from flask import Blueprint, abort, render_template
from flask_login import login_required

from app.data.threat_actors import (
    APT_ACTORS,
    HACKTIVIST_ACTORS,
    INCIDENTS,
    SECTOR_DISTRIBUTION,
    get_actor,
    localize_apt_actor,
    localize_hacktivist_actor,
    localize_incident,
    localize_sector,
)
from app.i18n import resolve_locale

threat_actors_bp = Blueprint("threat_actors", __name__)


def _localized_context(open_actor=None):
    locale = resolve_locale()
    incidents = sorted(INCIDENTS, key=lambda i: i["sort_key"])
    context = {
        "apt_actors": [localize_apt_actor(a, locale) for a in APT_ACTORS],
        "hacktivist_actors": [localize_hacktivist_actor(a, locale) for a in HACKTIVIST_ACTORS],
        "incidents": [localize_incident(i, locale) for i in incidents],
        "sector_distribution": [localize_sector(s, locale) for s in SECTOR_DISTRIBUTION],
    }
    if open_actor:
        context["open_actor"] = open_actor
    return context


@threat_actors_bp.route("/threat-actors")
@login_required
def index():
    return render_template("threat_actors.html", **_localized_context())


@threat_actors_bp.route("/threat-actors/<actor_id>")
@login_required
def detail(actor_id):
    actor = get_actor(actor_id)
    if actor is None:
        abort(404)
    return render_template("threat_actors.html", **_localized_context(open_actor=actor_id))
