"""Transactional email sending via Brevo API (https://www.brevo.com)."""

import logging
import os
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

logger = logging.getLogger(__name__)

DEFAULT_TEST_SENDER = "elmincfrlu@gmail.com"


class EmailResult:
    def __init__(self, ok: bool, detail: str = ""):
        self.ok = ok
        self.detail = detail


def send_email(to: str, subject: str, html: str) -> EmailResult:
    api_key = os.getenv("BREVO_API_KEY")
    if not api_key:
        logger.warning("BREVO_API_KEY not set — email not sent (dev mode). To: %s | Subject: %s", to, subject)
        return EmailResult(ok=False, detail="not_configured")

    from_address = os.getenv("EMAIL_FROM_ADDRESS", DEFAULT_TEST_SENDER)
    
    # Sendinblue / Brevo konfiqurasiyası
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = api_key
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to}],
        sender={"name": "AZ Threat Radar", "email": from_address},
        subject=subject,
        html_content=html
    )

    try:
        api_instance.send_transac_email(send_smtp_email)
        return EmailResult(ok=True)
    except ApiException as exc:
        logger.error("Brevo API xətası: %s | Status: %s | Body: %s", exc, exc.status, exc.body)
        print(f"BREVO ERROR: {exc.body}")
        return EmailResult(ok=False, detail="api_error")


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
