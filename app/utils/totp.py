"""TOTP (Time-based One-Time Password) helpers for two-factor
authentication. Uses the industry-standard pyotp library — compatible
with Google Authenticator, Microsoft Authenticator, Authy, and any other
TOTP-based authenticator app."""

import base64
import io
import secrets

import pyotp
import qrcode

ISSUER_NAME = "AZ Threat Radar"
BACKUP_CODE_COUNT = 8
# Excludes 0/O and 1/I to avoid transcription mistakes when a user types a
# backup code by hand from a printed/saved copy.
BACKUP_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER_NAME)


def get_qr_code_data_uri(uri: str) -> str:
    """Renders the provisioning URI as a PNG QR code and returns it as a
    base64 data: URI, ready to drop straight into an <img src="...">
    without needing a separate static file or route."""
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp_code(secret: str | None, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    """Returns plaintext one-time backup codes like 'A1B2-C3D4'. Callers
    are responsible for hashing before storage and showing these to the
    user exactly once — they cannot be retrieved again after that."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes