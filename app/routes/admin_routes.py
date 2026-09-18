from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.database.connection import db
from app.i18n import resolve_locale, translate
from app.models.report import Report
from app.models.search_history import SearchHistory
from app.models.threat_analysis import ThreatAnalysis
from app.models.user import User
from app.utils.decorators import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@login_required
@admin_required
def overview():
    total_users = User.query.count()
    total_admins = User.query.filter_by(is_admin=True).count()
    total_analyses = ThreatAnalysis.query.count()
    recent_users = User.query.order_by(User.id.desc()).limit(10).all()
    return render_template(
        "admin/overview.html",
        total_users=total_users,
        total_admins=total_admins,
        total_analyses=total_analyses,
        recent_users=recent_users,
    )


@admin_bp.route("/users")
@login_required
@admin_required
def users():
    q = (request.args.get("q") or "").strip().lower()
    query = User.query
    if q:
        query = query.filter(
            db.or_(User.email.ilike(f"%{q}%"), User.full_name.ilike(f"%{q}%"))
        )
    all_users = query.order_by(User.id.asc()).limit(300).all()
    return render_template("admin/users.html", users=all_users, q=q)


@admin_bp.route("/users/<int:user_id>")
@login_required
@admin_required
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    analyses_count = ThreatAnalysis.query.filter_by(user_id=user.id).count()
    return render_template("admin/user_detail.html", user=user, analyses_count=analyses_count)


@admin_bp.route("/users/<int:user_id>/toggle-admin", methods=["POST"])
@login_required
@admin_required
def toggle_admin(user_id):
    locale = resolve_locale()
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash(translate(locale, "admin.cannot_change_self"), "danger")
        return redirect(url_for("admin.users"))
    if user.is_admin:
        remaining = User.query.filter_by(is_admin=True).filter(User.id != user.id).count()
        if remaining == 0:
            flash(translate(locale, "admin.last_admin"), "danger")
            return redirect(url_for("admin.users"))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(translate(locale, "admin.role_updated"), "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@login_required
@admin_required
def toggle_active(user_id):
    locale = resolve_locale()
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash(translate(locale, "admin.cannot_change_self"), "danger")
        return redirect(url_for("admin.users"))
    user.is_active = not user.is_active
    db.session.commit()
    flash(translate(locale, "admin.status_updated"), "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    locale = resolve_locale()
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash(translate(locale, "admin.cannot_change_self"), "danger")
        return redirect(url_for("admin.users"))
    analyses = ThreatAnalysis.query.filter_by(user_id=user.id).all()
    for analysis in analyses:
        Report.query.filter_by(analysis_id=analysis.id).delete()
    SearchHistory.query.filter_by(user_id=user.id).delete()
    ThreatAnalysis.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash(translate(locale, "admin.user_deleted"), "success")
    return redirect(url_for("admin.users"))