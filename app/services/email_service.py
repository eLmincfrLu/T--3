"""Transactional email sending via the Resend HTTP API (https://resend.com).

No SDK dependency needed — Resend's API is a single plain HTTP POST, and
`requests` is already a project dependency.

Dev-mode fallback: if RESEND_API_KEY is not set in the environment, emails
are NOT silently dropped and verification is NOT silently bypassed — instead
send_email() returns ok=False with the rendered content attached, so callers
can show the link directly in the UI (clearly marked as a dev-mode
substitute for real delivery) while still requiring the same click-through
step. This keeps local development/testing possible without a Resend
account, without ever weakening the actual verification requirement.
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"
REQUEST_TIMEOUT = 10  # seconds

# Resend's shared sandbox sender. Until a custom domain is verified in the
# Resend dashboard, mail sent "from" this address can only be delivered TO
# the email address of the Resend account owner — any other recipient will
# be rejected by Resend. Verifying your own domain removes that restriction
# and lets EMAIL_FROM_ADDRESS be set to an address on that domain instead.
DEFAULT_TEST_SENDER = "AZ Threat Radar <onboarding@resend.dev>"


class EmailResult:
    def __init__(self, ok: bool, detail: str = ""):
        self.ok = ok
        self.detail = detail


def send_email(to: str, subject: str, html: str) -> EmailResult:
    api_key = os.getenv("RESEND_API_KEY")
    if not api_key:
        logger.warning("RESEND_API_KEY not set — email not sent (dev mode). To: %s | Subject: %s", to, subject)
        return EmailResult(ok=False, detail="not_configured")

    from_address = os.getenv("EMAIL_FROM_ADDRESS", DEFAULT_TEST_SENDER)
    try:
        resp = requests.post(
            RESEND_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={"from": from_address, "to": [to], "subject": subject, "html": html},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code >= 400:
            logger.error("Resend API error %s: %s", resp.status_code, resp.text[:500])
            return EmailResult(ok=False, detail=f"api_error_{resp.status_code}")
        return EmailResult(ok=True)
    except requests.RequestException as exc:
        logger.error("Resend API request failed: %s", exc)
        return EmailResult(ok=False, detail="network_error")


def _brand_wrapper(body_html: str) -> str:
    return f"""
    <div style="font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; max-width: 480px; margin: 0 auto;">
      <div style="background: #111827; padding: 20px 24px; border-radius: 8px 8px 0 0;">
        <span style="color: #ffffff; font-size: 18px; font-weight: 700; letter-spacing: 0.5px;">AZ THREAT RADAR</span>
      </div>
      <div style="background: #ffffff; border: 1px solid #e2e8f0; border-top: none; padding: 24px; border-radius: 0 0 8px 8px; color: #1e293b; font-size: 14px; line-height: 1.6;">
        {body_html}
      </div>
    </div>
    """


def build_verification_email(link: str, subject: str, heading: str, body: str, button_label: str, fallback_hint: str) -> str:
    return _brand_wrapper(f"""
        <h2 style="margin: 0 0 12px; font-size: 18px; color: #0f172a;">{heading}</h2>
        <p style="margin: 0 0 20px;">{body}</p>
        <p style="margin: 0 0 20px;">
          <a href="{link}" style="display:inline-block; background:#2563eb; color:#ffffff; text-decoration:none; padding:10px 20px; border-radius:6px; font-weight:600;">{button_label}</a>
        </p>
        <p style="margin: 0; color: #64748b; font-size: 12px;">{fallback_hint}<br><a href="{link}" style="color:#2563eb; word-break: break-all;">{link}</a></p>
    """)
