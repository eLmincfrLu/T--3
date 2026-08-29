from flask import Blueprint, abort, render_template
from flask_login import login_required

from app.data.threat_actors import (
    APT_ACTORS,
    HACKTIVIST_ACTORS,
    INCIDENTS,
    SECTOR_DISTRIBUTION,
    get_actor,
)

threat_actors_bp = Blueprint("threat_actors", __name__)


@threat_actors_bp.route("/threat-actors")
@login_required
def index():
    incidents = sorted(INCIDENTS, key=lambda i: i["sort_key"])
    return render_template(
        "threat_actors.html",
        apt_actors=APT_ACTORS,
        hacktivist_actors=HACKTIVIST_ACTORS,
        incidents=incidents,
        sector_distribution=SECTOR_DISTRIBUTION,
    )


@threat_actors_bp.route("/threat-actors/<actor_id>")
@login_required
def detail(actor_id):
    actor = get_actor(actor_id)
    if actor is None:
        abort(404)
    return render_template("threat_actors.html", apt_actors=APT_ACTORS,
                            hacktivist_actors=HACKTIVIST_ACTORS,
                            incidents=sorted(INCIDENTS, key=lambda i: i["sort_key"]),
                            sector_distribution=SECTOR_DISTRIBUTION,
                            open_actor=actor_id)