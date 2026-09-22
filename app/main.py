import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, flash, redirect, request, session, url_for
from flask_login import LoginManager, current_user, logout_user
from flask_session import Session
from flask_wtf.csrf import CSRFError

from app.database.connection import db, init_db, run_lightweight_migrations
from app.extensions import limiter, csrf
from app.models.user import User
from app.utils.helpers import safe_next
from app.routes.analysis_routes import analysis_bp
from app.routes.auth_routes import auth_bp
from app.routes.dashboard_routes import dashboard_bp
from app.routes.history_routes import history_bp
from app.routes.report_routes import report_bp
from app.routes.threat_actors_routes import threat_actors_bp
from app.routes.cve_routes import cve_bp
from app.routes.admin_routes import admin_bp
from app.i18n import LOCALE_LABELS, SUPPORTED_LOCALES, resolve_locale, translate
from app.services.auth_service import ensure_demo_user
from app.services.scheduler_service import init_scheduler

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    init_db(app)

    is_production = bool(os.getenv("DATABASE_URL"))

    app.config["SESSION_COOKIE_SECURE"] = is_production
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_SECURE"] = is_production
    app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True

    app.config["SESSION_TYPE"] = os.getenv("SESSION_TYPE", "filesystem")
    app.config["SESSION_FILE_DIR"] = str(Path(app.instance_path) / "flask_session")
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_USE_SIGNER"] = True
    Session(app)

    csrf.init_app(app)
    # Default 1 saatdır — admin panelin uzun müddət açıq qalan
    # tab-larında token vaxtının bitməsinin qarşısını alır.
    app.config["WTF_CSRF_TIME_LIMIT"] = None

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        flash(
            "Sessiyanın vaxtı bitib, zəhmət olmasa yenidən cəhd edin.",
            "warning",
        )
        return redirect(request.referrer or url_for("auth.login"))

    @app.url_defaults
    def add_static_version(endpoint, values):
        if endpoint == "static" and "filename" in values:
            file_path = os.path.join(app.static_folder, values["filename"])
            try:
                values["v"] = int(os.path.getmtime(file_path))
            except OSError:
                pass

    app.config["RATELIMIT_STORAGE_URI"] = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    limiter.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.before_request
    def enforce_active_account():
        # Admin tərəfindən deaktiv edilən hesabın aktiv sessiyası bu hook
        # olmadan işləməyə davam edərdi — bu boşluğu bağlayır.
        if current_user.is_authenticated and not current_user.is_active:
            logout_user()
            session.clear()
            flash(translate(resolve_locale(), "admin.account_disabled"), "danger")
            return redirect(url_for("auth.login"))

    # Admin hesabı YALNIZ idarəetmə üçündür — platformanın adi
    # funksiyalarından (dashboard, analiz, tarixçə, hesabat və s.) istifadə
    # edə bilməz. Bu route-lara birbaşa URL yazaraq da girməyə cəhd etsə,
    # avtomatik admin panelə yönləndirilir.
    ADMIN_ALLOWED_ENDPOINT_PREFIXES = ("admin.", "auth.logout", "auth.set_language")

    @app.before_request
    def restrict_admin_to_admin_panel():
        if (
            current_user.is_authenticated
            and current_user.is_admin
            and request.endpoint
            and request.endpoint != "static"
            and not request.endpoint.startswith(ADMIN_ALLOWED_ENDPOINT_PREFIXES)
        ):
            return redirect(url_for("admin.overview"))

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(threat_actors_bp)
    app.register_blueprint(cve_bp)
    app.register_blueprint(admin_bp)

    @app.errorhandler(429)
    def ratelimit_handler(_e):
        locale = resolve_locale()
        flash(translate(locale, "auth.rate_limited"), "danger")
        return redirect(safe_next(request.referrer) or url_for("auth.login"))

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'"
        )
        if is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.context_processor
    def inject_globals():
        locale = resolve_locale()

        def t(key, **kwargs):
            return translate(locale, key, **kwargs)

        return {
            "app_name": "AZ THREAT RADAR",
            "t": t,
            "current_locale": locale,
            "locale_labels": LOCALE_LABELS,
            "supported_locales": SUPPORTED_LOCALES,
        }

    with app.app_context():
        db.create_all()
        run_lightweight_migrations()
        ensure_demo_user()

    init_scheduler(app)

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(debug=True, host="0.0.0.0", port=5000)
