from flask_login import UserMixin

from app.database.connection import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False, default="")
    position = db.Column(db.String(255), nullable=False, default="")
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    backup_codes = db.Column(db.Text, nullable=True)
    notify_malicious_email = db.Column(db.Boolean, nullable=False, default=True)
    notify_weekly_summary = db.Column(db.Boolean, nullable=False, default=True)

    search_history = db.relationship("SearchHistory", back_populates="user", lazy="dynamic")
