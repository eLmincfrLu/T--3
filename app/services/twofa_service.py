"""Two-factor authentication (TOTP) service: setup, confirmation, ongoing
verification during login, and disabling. Backup codes are stored hashed
(same hashing as passwords) and each one is single-use."""

import json

from app.database.connection import db
from app.models.user import User
from app.utils.security import hash_password, verify_password
from app.utils.totp import (
    generate_backup_codes,
    generate_totp_secret,
    get_qr_code_data_uri,
    get_totp_uri,
    verify_totp_code,
)


def start_2fa_setup(user: User) -> tuple[str, str]:
    """Generates a fresh TOTP secret for the user and stores it, but does
    NOT activate 2FA yet — is_2fa_enabled only flips to True once
    confirm_2fa_setup() verifies the user actually scanned the QR code and
    can produce valid codes. Returns (manual_key, qr_code_data_uri)."""
    secret = generate_totp_secret()
    user.totp_secret = secret
    db.session.commit()
    uri = get_totp_uri(secret, user.email)
    qr_data_uri = get_qr_code_data_uri(uri)
    return secret, qr_data_uri


def confirm_2fa_setup(user: User, code: str) -> list[str] | None:
    """Verifies the code the user typed from their authenticator app. On
    success, generates backup codes, activates 2FA, and returns the
    plaintext backup codes (meant to be shown to the user exactly once).
    Returns None if the code was wrong."""
    if not user.totp_secret or not verify_totp_code(user.totp_secret, code):
        return None
    plaintext_codes = generate_backup_codes()
    hashed_entries = [{"hash": hash_password(c), "used": False} for c in plaintext_codes]
    user.backup_codes = json.dumps(hashed_entries)
    user.is_2fa_enabled = True
    db.session.commit()
    return plaintext_codes


def verify_2fa_code(user: User, code: str) -> bool:
    """Accepts either a live TOTP code or an unused backup code — both go
    through the same input field. Backup codes are single-use: a
    successful match marks that specific code consumed."""
    code = (code or "").strip()
    if not code:
        return False
    if verify_totp_code(user.totp_secret, code):
        return True

    if not user.backup_codes:
        return False
    normalized = code.upper()
    entries = json.loads(user.backup_codes)
    for entry in entries:
        if entry["used"]:
            continue
        if verify_password(entry["hash"], normalized):
            entry["used"] = True
            user.backup_codes = json.dumps(entries)
            db.session.commit()
            return True
    return False


def disable_2fa(user: User) -> None:
    user.totp_secret = None
    user.is_2fa_enabled = False
    user.backup_codes = None
    db.session.commit()