from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import login_required, current_user

from app.i18n import resolve_locale, translate
from app.database.connection import db
from app.models.threat_analysis import ThreatAnalysis
from app.services.auth_service import change_password, update_profile
from app.services.twofa_service import confirm_2fa_setup, disable_2fa, start_2fa_setup
from app.utils.helpers import utc_iso
from app.utils.security import verify_password

dashboard_bp = Blueprint("dashboard", __name__)


def _stats():
    analyses = ThreatAnalysis.query.filter_by(user_id=current_user.id).all()
    total = len(analyses)
    safe = sum(1 for a in analyses if a.risk_score <= 30)
    suspicious = sum(1 for a in analyses if 31 <= a.risk_score <= 70)
    malicious = sum(1 for a in analyses if a.risk_score >= 71)
    return total, safe, suspicious, malicious


def _country_distribution(user_id, limit=5):
    rows = (
        db.session.query(ThreatAnalysis.country, db.func.count(ThreatAnalysis.id))
        .filter(
            ThreatAnalysis.user_id == user_id,
            ThreatAnalysis.country.isnot(None),
            ThreatAnalysis.country != "",
        )
        .group_by(ThreatAnalysis.country)
        .order_by(db.func.count(ThreatAnalysis.id).desc())
        .limit(limit)
        .all()
    )
    return [{"name": c, "count": n} for c, n in rows]


def _daily_activity(user_id, days=14):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    analyses = ThreatAnalysis.query.filter(
        ThreatAnalysis.user_id == user_id, ThreatAnalysis.created_at >= since
    ).all()

    buckets = {}
    for i in range(days, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        buckets[day] = {"safe": 0, "suspicious": 0, "malicious": 0}

    for a in analyses:
        created = a.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        day = created.strftime("%Y-%m-%d")
        if day in buckets:
            buckets[day][a.risk_level()] += 1

    labels = list(buckets.keys())
    return {
        "labels": labels,
        "safe": [buckets[d]["safe"] for d in labels],
        "suspicious": [buckets[d]["suspicious"] for d in labels],
        "malicious": [buckets[d]["malicious"] for d in labels],
    }


@dashboard_bp.route("/dashboard")
@login_required
def index():
    total, safe, suspicious, malicious = _stats()
    recent = (
        ThreatAnalysis.query.filter_by(user_id=current_user.id)
        .order_by(ThreatAnalysis.created_at.desc())
        .limit(8)
        .all()
    )
    recent_searches = [
        {
            "target": a.target,
            "type": a.type,
            "risk_score": a.risk_score,
            "status": a.status,
            "date": utc_iso(a.created_at),
            "id": a.id,
        }
        for a in recent
    ]
    alerts = [r for r in recent_searches if r["status"] in ("SUSPICIOUS", "MALICIOUS")][:5]

    selected_days = request.args.get("days", 14, type=int)
    if selected_days not in (1, 7, 14, 30):
        selected_days = 14

    return render_template(
        "dashboard.html",
        stats={"total": total, "safe": safe, "suspicious": suspicious, "malicious": malicious},
        recent_searches=recent_searches,
        recent_alerts=alerts,
        risk_distribution={"safe": safe, "suspicious": suspicious, "malicious": malicious},
        country_distribution=_country_distribution(current_user.id),
        selected_days=selected_days,
    )


@dashboard_bp.route("/api/dashboard/summary")
@login_required
def api_summary():
    total, safe, suspicious, malicious = _stats()
    recent = (
        ThreatAnalysis.query.filter_by(user_id=current_user.id)
        .order_by(ThreatAnalysis.created_at.desc())
        .limit(10)
        .all()
    )
    categories = Counter()
    for a in recent:
        from app.utils.helpers import deserialize_payload

        payload = deserialize_payload(a.payload)
        for cat in payload.get("threat_categories") or []:
            if cat and cat != "None":
                categories[cat] += 1
    top_categories = [{"name": k, "count": v} for k, v in categories.most_common(5)]

    days = request.args.get("days", 14, type=int)
    if days not in (1, 7, 14, 30):
        days = 14

    return jsonify(
        {
            "stats": {
                "total": total,
                "safe": safe,
                "suspicious": suspicious,
                "malicious": malicious,
            },
            "top_categories": top_categories,
            "country_distribution": _country_distribution(current_user.id),
            "daily_activity": _daily_activity(current_user.id, days=days),
        }
    )

@dashboard_bp.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@dashboard_bp.route("/api/settings/notifications", methods=["POST"])
@login_required
def update_notification_settings():
    body = request.get_json(silent=True) or {}
    if "malicious" in body:
        current_user.notify_malicious_email = bool(body["malicious"])
    if "weekly" in body:
        current_user.notify_weekly_summary = bool(body["weekly"])
    db.session.commit()
    return jsonify(
        {
            "ok": True,
            "malicious": current_user.notify_malicious_email,
            "weekly": current_user.notify_weekly_summary,
        }
    )


@dashboard_bp.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@dashboard_bp.route("/settings/update-profile", methods=["POST"])
@login_required
def update_profile_page():
    full_name = request.form.get("full_name", "")
    position = request.form.get("position", "")
    locale = resolve_locale()
    err = update_profile(current_user, full_name, position, locale)
    if err:
        flash(err, "danger")
    else:
        flash(translate(locale, "settings.profile_updated"), "success")
    return redirect(url_for("dashboard.profile"))


@dashboard_bp.route("/settings/change-password", methods=["GET", "POST"])
@login_required
def change_password_page():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        locale = resolve_locale()
        if new_password != confirm_password:
            flash(translate(locale, "register.password_mismatch"), "danger")
        else:
            err = change_password(current_user, current_password, new_password, locale)
            if err:
                flash(err, "danger")
            else:
                flash(translate(locale, "settings.password_changed"), "success")
                return redirect(url_for("dashboard.profile"))
    return render_template("change_password.html")


@dashboard_bp.route("/profile/2fa/setup", methods=["GET", "POST"])
@login_required
def twofa_setup():
    locale = resolve_locale()
    if request.method == "POST":
        code = request.form.get("code", "")
        backup_codes = confirm_2fa_setup(current_user, code)
        if backup_codes:
            # Shown exactly once — stashed in the session and popped by
            # twofa_backup_codes() the moment that page is rendered.
            session["new_backup_codes"] = backup_codes
            flash(translate(locale, "twofa.enabled_success"), "success")
            return redirect(url_for("dashboard.twofa_backup_codes"))
        flash(translate(locale, "twofa.invalid_code"), "danger")
    secret, qr_data_uri = start_2fa_setup(current_user)
    return render_template("twofa_setup.html", secret=secret, qr_data_uri=qr_data_uri)


@dashboard_bp.route("/profile/2fa/backup-codes")
@login_required
def twofa_backup_codes():
    codes = session.pop("new_backup_codes", None)
    return render_template("twofa_backup_codes.html", codes=codes)


@dashboard_bp.route("/profile/2fa/disable", methods=["GET", "POST"])
@login_required
def twofa_disable():
    locale = resolve_locale()
    if request.method == "POST":
        password = request.form.get("password", "")
        if not verify_password(current_user.password_hash, password):
            flash(translate(locale, "settings.current_password_wrong"), "danger")
        else:
            disable_2fa(current_user)
            flash(translate(locale, "twofa.disabled_success"), "success")
            return redirect(url_for("dashboard.profile"))
    return render_template("twofa_disable.html")
