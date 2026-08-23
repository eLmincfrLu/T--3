import io
from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF
from flask import Blueprint, Response, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from app.i18n import resolve_locale, translate
from app.database.connection import db
from app.models.report import Report
from app.models.threat_analysis import ThreatAnalysis
from app.utils.helpers import deserialize_payload, utc_iso

report_bp = Blueprint("reports", __name__)

# Unicode TTF fonts bundled with the app so PDF exports can render the full
# Azerbaijani alphabet (ə, ğ, ş, ç, ö, ü, ı, İ) as well as Cyrillic (ru locale).
# The built-in PDF core fonts (Helvetica/Times/Courier) only support Latin-1
# and raise FPDFUnicodeEncodingException on these characters.
FONTS_DIR = Path(__file__).resolve().parent.parent / "static" / "fonts"
FONT_REGULAR = FONTS_DIR / "DejaVuSans.ttf"
FONT_BOLD = FONTS_DIR / "DejaVuSans-Bold.ttf"


@report_bp.route("/reports")
@login_required
def index():
    saved = (
        Report.query.join(ThreatAnalysis, Report.analysis_id == ThreatAnalysis.id)
        .filter(ThreatAnalysis.user_id == current_user.id)
        .order_by(Report.created_at.desc())
        .limit(50)
        .all()
    )
    return render_template("reports.html", saved_reports=saved)


@report_bp.route("/reports/save/<int:analysis_id>", methods=["POST"])
@login_required
def save_report(analysis_id):
    analysis = ThreatAnalysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        abort(404)
    report = Report(analysis_id=analysis.id, title=f"Report — {analysis.target}")
    db.session.add(report)
    db.session.commit()
    flash(translate(resolve_locale(), "reports.saved_success"), "success")
    return redirect(url_for("reports.index"))


@report_bp.route("/reports/export/csv")
@login_required
def export_csv():
    locale = resolve_locale()
    analyses = (
        ThreatAnalysis.query.filter_by(user_id=current_user.id)
        .order_by(ThreatAnalysis.created_at.desc())
        .all()
    )
    if not analyses:
        flash(translate(locale, "reports.empty"), "warning")
        return redirect(url_for("reports.index"))

    output = io.StringIO()
    output.write("\ufeff")  # UTF-8 BOM — Excel-də AZ hərflərinin (ə, ö, ü) düzgün görünməsi üçün
    import csv

    writer = csv.writer(output)
    writer.writerow(
        [
            translate(locale, "common.target"),
            translate(locale, "common.type"),
            translate(locale, "result.risk_score"),
            translate(locale, "common.status"),
            translate(locale, "result.country"),
            translate(locale, "common.date"),
        ]
    )
    for a in analyses:
        writer.writerow(
            [a.target, a.type, a.risk_score, a.status, a.country or "", utc_iso(a.created_at)]
        )
    return Response(
        output.getvalue().encode("utf-8"),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=threat_analyses.csv"},
    )


def _status_rgb(status: str) -> tuple[int, int, int]:
    s = (status or "").upper()
    if s == "SAFE":
        return (34, 197, 94)
    if s == "SUSPICIOUS":
        return (245, 158, 11)
    if s == "MALICIOUS":
        return (239, 68, 68)
    return (148, 163, 184)


STATUS_TRANSLATION_KEYS = {
    "SAFE": "status.safe",
    "SUSPICIOUS": "status.suspicious",
    "MALICIOUS": "status.malicious",
}

TYPE_TRANSLATION_KEYS = {
    "ip": "analysis.type_ip",
    "domain": "analysis.type_domain",
    "url": "analysis.type_url",
}


def _t_status(locale: str, status: str) -> str:
    key = STATUS_TRANSLATION_KEYS.get((status or "").upper())
    return translate(locale, key) if key else (status or "")


def _t_type(locale: str, type_: str) -> str:
    key = TYPE_TRANSLATION_KEYS.get((type_ or "").lower())
    return translate(locale, key) if key else (type_ or "")


def _register_unicode_font(pdf: FPDF) -> str:
    """Register a Unicode TTF font so the full Azerbaijani alphabet (ə, ğ, ş,
    ç, ö, ü, ı, İ) and Cyrillic text render correctly. The built-in PDF core
    fonts (Helvetica/Times/Courier) only support Latin-1 and raise
    FPDFUnicodeEncodingException for these characters."""
    if FONT_REGULAR.exists() and FONT_BOLD.exists():
        pdf.add_font("DejaVu", "", str(FONT_REGULAR))
        pdf.add_font("DejaVu", "B", str(FONT_BOLD))
        return "DejaVu"
    # Fallback so the app still produces a PDF (with limited character
    # support) even if the bundled font files are ever missing.
    return "Helvetica"


def _build_pdf(analysis: ThreatAnalysis, data: dict, locale: str) -> bytes:
    rec_code = data.get("recommendation")
    rec_text = (
        translate(locale, f"result.recommendation.{rec_code.lower()}")
        if rec_code
        else translate(locale, "common.unknown")
    )
    status_color = _status_rgb(analysis.status)
    unknown = translate(locale, "common.unknown")
    na = translate(locale, "common.not_available")

    pdf = FPDF(format="A4", unit="mm")
    font = _register_unicode_font(pdf)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # --- Header band (matches --card dark theme) ---
    pdf.set_fill_color(17, 24, 39)
    pdf.rect(0, 0, 210, 28, "F")
    pdf.set_xy(12, 8)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(font, "B", 18)
    pdf.cell(0, 8, "AZ THREAT RADAR", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(12)
    pdf.set_font(font, "", 10)
    pdf.set_text_color(180, 190, 210)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.cell(
        0, 6,
        f"{translate(locale, 'reports.pdf_report_title')} — {translate(locale, 'reports.pdf_generated_on')} {generated_at}",
    )

    pdf.set_y(36)
    pdf.set_x(12)
    pdf.set_text_color(15, 23, 42)

    # --- Target block ---
    pdf.set_font(font, "B", 14)
    pdf.cell(0, 8, str(analysis.target), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(12)
    pdf.set_font(font, "", 10)
    pdf.set_text_color(100, 110, 130)
    pdf.cell(0, 6, f"{translate(locale, 'common.type')}: {_t_type(locale, analysis.type)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # --- Risk score + status badges ---
    pdf.set_x(12)
    pdf.set_fill_color(*status_color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(font, "B", 11)
    pdf.cell(55, 9, f"{translate(locale, 'result.risk_score')}: {analysis.risk_score}", fill=True, align="C")
    pdf.cell(4)
    pdf.cell(45, 9, _t_status(locale, analysis.status), fill=True, align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # --- Recommendation banner ---
    pdf.set_x(12)
    pdf.set_text_color(15, 23, 42)
    pdf.set_font(font, "B", 11)
    pdf.cell(0, 7, translate(locale, "result.recommendations"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(12)
    pdf.set_font(font, "", 10)
    pdf.set_fill_color(241, 245, 249)
    pdf.multi_cell(186, 6, rec_text, fill=True)
    pdf.ln(4)

    def section(title, rows):
        pdf.set_x(12)
        pdf.set_font(font, "B", 11)
        pdf.set_text_color(37, 99, 235)
        pdf.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(226, 232, 240)
        pdf.line(12, pdf.get_y(), 198, pdf.get_y())
        pdf.ln(2)
        pdf.set_font(font, "", 10)
        pdf.set_text_color(30, 41, 59)
        for label, value in rows:
            pdf.set_x(12)
            if label:
                pdf.set_font(font, "B", 10)
                pdf.cell(45, 6, label)
                pdf.set_font(font, "", 10)
                pdf.multi_cell(141, 6, str(value) if value not in (None, "") else unknown)
            else:
                pdf.multi_cell(186, 6, str(value) if value not in (None, "") else unknown)
        pdf.ln(3)

    section(translate(locale, "reports.section_network"), [
        (translate(locale, "result.country"), data.get("country") or unknown),
        (translate(locale, "result.isp"), data.get("isp") or unknown),
        (translate(locale, "result.asn"), data.get("asn") or unknown),
        (translate(locale, "result.hostname"), data.get("hostname") or unknown),
    ])

    section(translate(locale, "result.categories"), [
        (None, ", ".join(data.get("threat_categories") or []) or translate(locale, "common.none")),
    ])

    whois = data.get("whois") or {}
    section(translate(locale, "result.whois"), [
        (translate(locale, "result.registrar"), whois.get("registrar") or unknown),
        (translate(locale, "result.registration_date"), whois.get("registration_date") or unknown),
        (translate(locale, "result.expiration_date"), whois.get("expiration_date") or unknown),
    ])

    rep = data.get("reputation") or {}
    section(translate(locale, "result.reputation"), [
        (translate(locale, "result.virustotal"), rep.get("virustotal_status") or na),
        (translate(locale, "result.blacklist"), rep.get("blacklist_status") or na),
        (translate(locale, "result.malware"), rep.get("malware_detection") or na),
        (translate(locale, "result.phishing"), rep.get("phishing_detection") or na),
        (translate(locale, "result.spam"), rep.get("spam_detection") or na),
    ])

    pdf.set_y(-15)
    pdf.set_font(font, "", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 10, translate(locale, "reports.pdf_footer"), align="C")

    return bytes(pdf.output())


@report_bp.route("/reports/export/pdf/<int:analysis_id>")
@login_required
def export_pdf(analysis_id):
    analysis = ThreatAnalysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        abort(404)
    data = deserialize_payload(analysis.payload)
    locale = resolve_locale()
    pdf_bytes = _build_pdf(analysis, data, locale)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=report_{analysis_id}.pdf",
        },
    )