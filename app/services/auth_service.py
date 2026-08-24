import os
from flask import url_for

from app.database.connection import db
from app.models.user import User
from app.services.email_service import EmailResult, build_verification_email, send_email
from app.utils.security import hash_password, verify_password
from app.utils.tokens import generate_email_verification_token, verify_email_verification_token
from app.i18n import format_password_errors, translate
from app.utils.validators import validate_email, validate_password, validate_required_text

DEFAULT_DEMO_EMAIL = "123@holbertonstudents.com"
DEFAULT_DEMO_PASSWORD = "Holbie123!"
DEFAULT_DEMO_FULL_NAME = "Demo İstifadəçi"
DEFAULT_DEMO_POSITION = "Tələbə"


def ensure_demo_user():
    user = User.query.filter_by(email=DEFAULT_DEMO_EMAIL).first()
    if user:
        return user
    user = User(
        email=DEFAULT_DEMO_EMAIL,
        password_hash=hash_password(DEFAULT_DEMO_PASSWORD),
        full_name=DEFAULT_DEMO_FULL_NAME,
        position=DEFAULT_DEMO_POSITION,
        email_verified=True,  # demo account skips the email verification step
    )
    db.session.add(user)
    db.session.commit()
    return user


def authenticate(email: str, password: str) -> User | None:
    user = User.query.filter_by(email=email.strip().lower()).first()
    if user and verify_password(user.password_hash, password):
        return user
    return None


def register_user(
    email: str, password: str, full_name: str, position: str, locale: str
) -> tuple[User | None, str | None]:
    ok, email_or_err = validate_email(email)
    if not ok:
        return None, translate(locale, email_or_err)
    ok, full_name_or_err = validate_required_text(full_name, "validation.full_name_required")
    if not ok:
        return None, translate(locale, full_name_or_err)
    ok, position_or_err = validate_required_text(position, "validation.position_required")
    if not ok:
        return None, translate(locale, position_or_err)
    ok, pwd_errors = validate_password(password)
    if not ok:
        return None, format_password_errors(locale, pwd_errors)
    if User.query.filter_by(email=email_or_err).first():
        return None, translate(locale, "register.email_taken")
    user = User(
        email=email_or_err,
        password_hash=hash_password(password),
        full_name=full_name_or_err,
        position=position_or_err,
        email_verified=False,
    )
    db.session.add(user)
    db.session.commit()
    return user, None


def send_verification_email(user: User, locale: str) -> tuple[EmailResult, str]:
    """Generates a fresh verification token/link and emails it to the user.
    Uses APP_URL from environment if defined to support cross-device testing."""
    token = generate_email_verification_token(user.email)
    
    app_url = os.getenv("APP_URL")
    if app_url:
        link = f"{app_url.rstrip('/')}/verify-email/{token}"
    else:
        link = url_for("auth.verify_email", token=token, _external=True)
    print(f"\n=======================\n GENERATED LINK: {link} \n=======================\n")

    subject = translate(locale, "verify.email_subject")
    html = build_verification_email(
        link=link,
        subject=subject,
        heading=translate(locale, "verify.email_heading"),
        body=translate(locale, "verify.email_body"),
        button_label=translate(locale, "verify.email_button"),
        fallback_hint=translate(locale, "verify.email_fallback_hint"),
    )
    result = send_email(user.email, subject, html)
    return result, link


def resolve_verification_token(token: str) -> tuple[User | None, bool]:
    """Returns (user, expired). user is None if the token is invalid/tampered
    or no longer matches an existing account."""
    email, expired = verify_email_verification_token(token)
    if not email:
        return None, False
    user = User.query.filter_by(email=email).first()
    return user, expired


def mark_email_verified(user: User) -> None:
    user.email_verified = True
    db.session.commit()


def update_profile(user: User, full_name: str, position: str, locale: str) -> str | None:
    ok, full_name_or_err = validate_required_text(full_name, "validation.full_name_required")
    if not ok:
        return translate(locale, full_name_or_err)
    ok, position_or_err = validate_required_text(position, "validation.position_required")
    if not ok:
        return translate(locale, position_or_err)
    user.full_name = full_name_or_err
    user.position = position_or_err
    db.session.commit()
    return None


def change_password(user: User, current_password: str, new_password: str, locale: str) -> str | None:
    if not verify_password(user.password_hash, current_password):
        return translate(locale, "settings.current_password_wrong")
    ok, pwd_errors = validate_password(new_password)
    if not ok:
        return format_password_errors(locale, pwd_errors)
    user.password_hash = hash_password(new_password)
    db.session.commit()
    return None