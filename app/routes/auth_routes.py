from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import limiter
from app.i18n import SUPPORTED_LOCALES, DEFAULT_LOCALE, resolve_locale, translate
from app.models.user import User
from app.services.auth_service import (
    authenticate,
    mark_email_verified,
    register_user,
    resolve_verification_token,
    send_verification_email,
)

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/")
def landing():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    return render_template("landing.html")

@auth_bp.route("/login", methods=["GET", "POST"])
# Brute-force protection: only POST attempts (actual login submissions) are
# throttled — GET requests to view the login page are never rate limited.
@limiter.limit("10 per minute;30 per hour", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"
        locale = resolve_locale()
        user = authenticate(email, password)
        if user:
            if not user.email_verified:
                flash(translate(locale, "login.email_not_verified"), "warning")
                return redirect(url_for("auth.verify_pending", email=user.email))
            login_user(user, remember=remember)
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard.index"))
        flash(translate(locale, "login.invalid_credentials"), "danger")
    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
# Abuse protection: only POST attempts (actual registration submissions) are
# throttled — GET requests to view the register page are never rate limited.
@limiter.limit("5 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        email = request.form.get("email", "")
        full_name = request.form.get("full_name", "")
        position = request.form.get("position", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        locale = resolve_locale()
        if password != confirm:
            flash(translate(locale, "register.password_mismatch"), "danger")
        else:
            user, err = register_user(email, password, full_name, position, locale)
            if user:
                result, link = send_verification_email(user, locale)
                if result.ok:
                    flash(translate(locale, "verify.sent", email=user.email), "success")
                elif result.detail == "not_configured":
                    # Dev mode: no RESEND_API_KEY configured yet. Verification
                    # is still required — we just surface the link directly
                    # instead of emailing it, so the flow stays testable.
                    flash(translate(locale, "verify.dev_mode_link", link=link), "warning")
                else:
                    flash(translate(locale, "verify.send_failed"), "warning")
                return redirect(url_for("auth.verify_pending", email=user.email))
            flash(err, "danger")
    return render_template("register.html")


@auth_bp.route("/verify-pending")
def verify_pending():
    return render_template("verify_pending.html", email=request.args.get("email", ""))


@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    locale = resolve_locale()
    user, expired = resolve_verification_token(token)
    if not user:
        flash(translate(locale, "verify.invalid_link"), "danger")
        return redirect(url_for("auth.login"))
    if user.email_verified:
        flash(translate(locale, "verify.already_verified"), "info")
        return redirect(url_for("auth.login"))
    if expired:
        flash(translate(locale, "verify.link_expired"), "warning")
        return redirect(url_for("auth.verify_pending", email=user.email))
    mark_email_verified(user)
    flash(translate(locale, "verify.success"), "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/resend-verification", methods=["POST"])
# Abuse protection: an unauthenticated endpoint that triggers an outbound
# email — keep it tightly throttled per IP.
@limiter.limit("3 per hour")
def resend_verification():
    locale = resolve_locale()
    email = (request.form.get("email") or "").strip().lower()
    user = User.query.filter_by(email=email).first() if email else None
    if user and not user.email_verified:
        send_verification_email(user, locale)
    # Always show the same generic confirmation regardless of whether the
    # account exists or is already verified, to avoid leaking which emails
    # are registered.
    flash(translate(locale, "verify.resend_sent"), "success")
    return redirect(url_for("auth.verify_pending", email=email))


@auth_bp.route("/set-language/<lang>")
def set_language(lang):
    if lang not in SUPPORTED_LOCALES:
        lang = DEFAULT_LOCALE
    next_url = request.args.get("next") or request.referrer or url_for("auth.login")
    response = redirect(next_url)
    response.set_cookie("lang", lang, max_age=365 * 24 * 3600, samesite="Lax")
    return response


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))