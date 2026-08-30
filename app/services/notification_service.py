"""Wires the two 'Bildirişlər' (Notifications) toggles in Settings to real
email sends: an immediate alert when a scan comes back MALICIOUS, and a
weekly digest of the past 7 days' scans. Both re-use the existing Brevo
email_service.py — this module only decides *when* to send and builds the
email content.
"""

import os
from datetime import datetime, timedelta, timezone

from flask import url_for

from app.i18n import DEFAULT_LOCALE, translate
from app.models.threat_analysis import ThreatAnalysis
from app.models.user import User
from app.services.email_service import build_malicious_alert_email, build_weekly_summary_email, send_email


def _app_url(path: str) -> str:
    """Builds an absolute link for use in emails. Prefers url_for when
    called inside a request (normal case for the malicious-alert email);
    falls back to APP_URL for the weekly digest, which runs outside any
    request context in the background scheduler."""
    app_url = os.getenv("APP_URL")
    if app_url:
        return f"{app_url.rstrip('/')}{path}"
    try:
        return url_for("dashboard.index", _external=True).rstrip("/") + path
    except RuntimeError:
        return f"http://localhost:5000{path}"


def maybe_send_malicious_alert(user: User, analysis: ThreatAnalysis, locale: str = DEFAULT_LOCALE) -> None:
    """Sends the 'Zərərli təhdid aşkarlananda e-poçt göndər' alert for a
    single freshly-created analysis, if the user has opted in, verified
    their email, and this particular scan came back MALICIOUS. Never
    raises — a failed/unconfigured email send should never break the
    analysis flow the user is waiting on."""
    if analysis.status != "MALICIOUS":
        return
    if not user.notify_malicious_email or not user.email_verified:
        return

    link = _app_url(url_for("analysis.result", analysis_id=analysis.id))
    subject = translate(locale, "notify.malicious_subject")
    html = build_malicious_alert_email(
        link=link,
        heading=translate(locale, "notify.malicious_heading"),
        body=translate(locale, "notify.malicious_body"),
        target_label=translate(locale, "common.target"),
        target=analysis.target,
        risk_label=translate(locale, "common.risk"),
        risk_score=analysis.risk_score,
        button_label=translate(locale, "notify.malicious_button"),
    )
    try:
        send_email(user.email, subject, html)
    except Exception:  # pragma: no cover - never let a notification failure break analysis
        pass


def send_weekly_summaries(app) -> int:
    """Sends the 'Həftəlik xülasə' digest to every opted-in, verified user
    who ran at least one scan in the past 7 days. Meant to be called from
    the background scheduler (see scheduler_service.py) — takes the Flask
    app explicitly since a scheduled job runs outside any request context.
    Returns the number of emails sent (useful for logging/testing)."""
    sent = 0
    with app.app_context():
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        users = User.query.filter_by(notify_weekly_summary=True, email_verified=True).all()
        for user in users:
            analyses = ThreatAnalysis.query.filter(
                ThreatAnalysis.user_id == user.id,
                ThreatAnalysis.created_at >= cutoff,
            ).all()
            if not analyses:
                continue

            total = len(analyses)
            malicious = sum(1 for a in analyses if a.status == "MALICIOUS")
            suspicious = sum(1 for a in analyses if a.status == "SUSPICIOUS")
            safe = sum(1 for a in analyses if a.status == "SAFE")

            locale = DEFAULT_LOCALE
            link = _app_url("/history")
            subject = translate(locale, "notify.weekly_subject")
            stat_rows = [
                (translate(locale, "notify.weekly_stat_total"), str(total), "#0f172a"),
                (translate(locale, "notify.weekly_stat_malicious"), str(malicious), "#b91c1c"),
                (translate(locale, "notify.weekly_stat_suspicious"), str(suspicious), "#b45309"),
                (translate(locale, "notify.weekly_stat_safe"), str(safe), "#15803d"),
            ]
            html = build_weekly_summary_email(
                link=link,
                heading=translate(locale, "notify.weekly_heading"),
                body=translate(locale, "notify.weekly_body_intro", count=total),
                stat_rows=stat_rows,
                button_label=translate(locale, "notify.weekly_button"),
            )
            try:
                result = send_email(user.email, subject, html)
                if result.ok:
                    sent += 1
            except Exception:  # pragma: no cover - one user's failure shouldn't skip the rest
                continue
    return sent