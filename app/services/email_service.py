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
        <div style="text-align: center; margin: 25px 0;">
          <a href="{link}" target="_blank" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
            {button_label}
          </a>
        </div>
        <p style="margin: 20px 0 0; color: #64748b; font-size: 12px; word-break: break-all;">
          {fallback_hint}<br>
          <a href="{link}" style="color: #2563eb;">{link}</a>
        </p>
    """)


def build_password_reset_email(link: str, heading: str, body: str, action_line: str) -> str:
    return _brand_wrapper(f"""
        <h2 style="margin: 0 0 12px; font-size: 18px; color: #0f172a;">{heading}</h2>
        <p style="margin: 0 0 16px;">{body}</p>
        <p style="margin: 0 0 8px; font-weight: 600; color: #334155;">{action_line}</p>
        <div style="background: #f1f5f9; padding: 12px; border-radius: 6px; word-break: break-all; font-family: monospace; font-size: 13px; color: #2563eb;">
          {link}
        </div>
    """)


def build_malicious_alert_email(link: str, heading: str, body: str, target_label: str, target: str,
                                 risk_label: str, risk_score: int, button_label: str) -> str:
    return _brand_wrapper(f"""
        <div style="display: inline-block; background: #fee2e2; color: #b91c1c; font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 20px; margin-bottom: 12px;">
          {risk_label}
        </div>
        <h2 style="margin: 0 0 12px; font-size: 18px; color: #0f172a;">{heading}</h2>
        <p style="margin: 0 0 16px;">{body}</p>
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 16px; margin-bottom: 20px;">
          <div style="font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px;">{target_label}</div>
          <div style="font-family: monospace; font-size: 14px; color: #0f172a; word-break: break-all; margin-bottom: 10px;">{target}</div>
          <div style="font-size: 12px; color: #64748b;">{risk_label}: <strong style="color: #b91c1c;">{risk_score}/100</strong></div>
        </div>
        <div style="text-align: center;">
          <a href="{link}" target="_blank" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
            {button_label}
          </a>
        </div>
    """)


def build_weekly_summary_email(link: str, heading: str, body: str, stat_rows: list[tuple[str, str, str]],
                                button_label: str) -> str:
    rows_html = "".join(
        f"""
        <tr>
          <td style="padding: 10px 0; border-bottom: 1px solid #e2e8f0; color: #334155;">{label}</td>
          <td style="padding: 10px 0; border-bottom: 1px solid #e2e8f0; text-align: right; font-weight: 700; color: {color};">{value}</td>
        </tr>
        """
        for label, value, color in stat_rows
    )
    return _brand_wrapper(f"""
        <h2 style="margin: 0 0 12px; font-size: 18px; color: #0f172a;">{heading}</h2>
        <p style="margin: 0 0 16px;">{body}</p>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
          {rows_html}
        </table>
        <div style="text-align: center;">
          <a href="{link}" target="_blank" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
            {button_label}
          </a>
        </div>
    """)