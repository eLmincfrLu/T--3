"""Runs the weekly summary email on a schedule using APScheduler, so the
'Həftəlik xülasə' toggle in Settings is backed by an actual recurring job
rather than doing nothing. Kept intentionally small: one background
scheduler, one weekly job, started once per real process.
"""

import logging
import os

from apscheduler.schedulers.background import BackgroundScheduler

from app.services.notification_service import send_weekly_summaries

logger = logging.getLogger(__name__)

_scheduler = None


def init_scheduler(app) -> None:
    """Starts the background scheduler exactly once per real process.

    Flask's debug reloader spawns a watcher process and a worker process;
    without the WERKZEUG_RUN_MAIN check below the job would be registered
    twice (and fire emails twice) whenever debug=True. In production
    (no reloader) app.debug is False, so it always starts normally.
    """
    global _scheduler
    if _scheduler is not None:
        return
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        func=lambda: send_weekly_summaries(app),
        trigger="cron",
        day_of_week="mon",
        hour=8,
        minute=0,
        id="weekly_summary_email",
        replace_existing=True,
    )
    scheduler.start()
    _scheduler = scheduler
    logger.info("Weekly summary scheduler started (runs Mondays 08:00 UTC).")