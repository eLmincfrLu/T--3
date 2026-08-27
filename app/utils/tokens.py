"""Signed, stateless tokens (no database table needed) built on itsdangerous —
already a transitive dependency of Flask. Used for links that must prove the
bearer controls a given email address (e.g. email verification) within a
limited time window.
"""

from flask import current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

EMAIL_VERIFY_SALT = "email-verify"
EMAIL_VERIFY_MAX_AGE = 24 * 3600  # 24 hours

PASSWORD_RESET_SALT = "password-reset"
PASSWORD_RESET_MAX_AGE = 3600  # 1 hour — shorter-lived than email verification


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def generate_email_verification_token(email: str) -> str:
    return _serializer().dumps(email.strip().lower(), salt=EMAIL_VERIFY_SALT)


def verify_email_verification_token(token: str, max_age: int = EMAIL_VERIFY_MAX_AGE):
    """Returns (email, expired) where:
    - (email, False): token is valid and unexpired — email confirmed.
    - (email, True): token was valid but has expired — email recovered
      anyway so the UI can offer to resend without asking the user to
      retype it.
    - (None, False): token is invalid/tampered — nothing recoverable.
    """
    serializer = _serializer()
    try:
        email = serializer.loads(token, salt=EMAIL_VERIFY_SALT, max_age=max_age)
        return email, False
    except SignatureExpired as e:
        # The signature/timestamp is valid but past max_age — recover the
        # original email from the (already-verified) raw payload so the UI
        # can offer a resend without asking the user to retype it. Note:
        # SignatureExpired.payload is the raw signed bytes, not yet run
        # through JSON deserialization — that's what load_payload() does.
        try:
            return serializer.load_payload(e.payload), True
        except BadSignature:
            return None, False
    except BadSignature:
        return None, False


def generate_password_reset_token(email: str) -> str:
    return _serializer().dumps(email.strip().lower(), salt=PASSWORD_RESET_SALT)


def verify_password_reset_token(token: str, max_age: int = PASSWORD_RESET_MAX_AGE):
    """Same contract as verify_email_verification_token, but for the
    password-reset flow and a shorter max_age (see PASSWORD_RESET_MAX_AGE).
    Returns (email, expired):
    - (email, False): token valid and unexpired.
    - (email, True): token was valid but has expired.
    - (None, False): token invalid/tampered.
    """
    serializer = _serializer()
    try:
        email = serializer.loads(token, salt=PASSWORD_RESET_SALT, max_age=max_age)
        return email, False
    except SignatureExpired as e:
        try:
            return serializer.load_payload(e.payload), True
        except BadSignature:
            return None, False
    except BadSignature:
        return None, False