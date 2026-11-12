"""PDF Scan Report Generation Service for PhishGuard AI.

Generates a formal, cybersecurity-styled PDF report summarizing the structural
and lexical URL feature analysis and dual-classifier machine learning predictions.
"""

from datetime import datetime
from io import BytesIO
from typing import Optional
from fpdf import FPDF

from src.phishguard.services.url_analyzer import URLAnalysisReport
from config import PROJECT_NAME, FULL_PROJECT_TITLE, TAGLINE


class PhishGuardPDF(FPDF):
    """Custom PDF template with cybersecurity headers and footers."""

    def header(self):
        # Header banner
        self.set_fill_color(15, 23, 42)  # Navy dark #0F172A
        self.rect(0, 0, 210, 24, "F")
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(56, 189, 248)  # Cyan #38BDF8
        self.set_xy(10, 6)
        self.cell(100, 8, f"{PROJECT_NAME} - Security Intelligence Report", ln=0)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(148, 163, 184)  # Slate #94A3B8
        self.set_xy(120, 6)
        self.cell(80, 8, TAGLINE, align="R", ln=1)
        self.ln(12)

    def footer(self):
        self.set_y(-18)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(
            0,
            5,
            "Confidentiality Notice: URL evaluated via static lexical parsing. No target websites were visited or contacted.",
            align="C",
            ln=1
        )
        self.cell(0, 5, f"Page {self.page_no()}", align="C")


def generate_scan_pdf_report(report: URLAnalysisReport) -> bytes:
    """Compiles a complete URLAnalysisReport into formatted PDF bytes.

    Args:
        report: URLAnalysisReport instance from url_analyzer.

    Returns:
        bytes: Raw PDF file bytes ready for download.
    """
    pdf = PhishGuardPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Document Title & Subtitle
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 7, "URL Cybersecurity Assessment Report", ln=1)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(0, 4.5, FULL_PROJECT_TITLE)
    pdf.ln(3)

    # Metadata Strip
    pdf.set_fill_color(241, 245, 249)  # Light slate background
    pdf.rect(10, pdf.get_y(), 190, 18, "F")
    pdf.set_xy(14, pdf.get_y() + 2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(32, 5, "Scan Date & Time:", ln=0)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(51, 65, 85)
    scan_dt = report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if report.timestamp else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    pdf.cell(60, 5, scan_dt, ln=0)

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(32, 5, "Execution Mode:", ln=0)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(50, 5, "Static URL Lexical Analysis (0 Network)", ln=1)

    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(32, 5, "Target URL:", ln=0)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(14, 116, 144)
    display_url = report.normalized_url[:80] + ("..." if len(report.normalized_url) > 80 else "")
    pdf.cell(140, 5, display_url, ln=1)
    pdf.ln(6)

    # 1. Executive Summary & Machine Learning Classification
    pred = report.prediction_result
    final_verdict = pred.final_prediction_name if pred else "Unable to Classify"
    is_phish = (final_verdict == "Phishing")

    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "1. Supervised Machine Learning Verdict", ln=1)

    # Verdict Box
    box_color = (254, 242, 242) if is_phish else (240, 253, 244)
    border_color = (239, 68, 68) if is_phish else (16, 185, 129)
    text_color = (185, 28, 28) if is_phish else (21, 128, 61)
    verdict_label = "POTENTIAL PHISHING DETECTED" if is_phish else "LIKELY LEGITIMATE (LOW RISK)"

    pdf.set_fill_color(*box_color)
    pdf.set_draw_color(*border_color)
    pdf.set_line_width(0.6)
    pdf.rect(10, pdf.get_y(), 190, 24, "DF")

    pdf.set_xy(15, pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*text_color)
    pdf.cell(0, 6, verdict_label, ln=1)

    pdf.set_x(15)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(51, 65, 85)
    consensus_text = "Consensus: Both Decision Tree and Random Forest classifiers agreed." if (pred and pred.consensus) else "Notice: Model disagreement detected; defaulting to ensemble Random Forest."
    pdf.cell(0, 5, consensus_text, ln=1)

    pdf.set_x(15)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 116, 139)
    disclaimer_note = "Assessment is based on 18 static lexical features. It does not replace antivirus software or guarantee website authenticity."
    pdf.cell(0, 4.5, disclaimer_note, ln=1)
    pdf.ln(6)

    # Dual Model Breakdown Cards
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(92, 5, "Decision Tree Classifier (CART)", ln=0)
    pdf.cell(6, 5, "", ln=0)
    pdf.cell(92, 5, "Random Forest Classifier (Ensemble)", ln=1)

    dt_pred = pred.dt.prediction_name if pred else "N/A"
    dt_conf = f"{pred.dt.confidence:.1%}" if pred else "N/A"
    rf_pred = pred.rf.prediction_name if pred else "N/A"
    rf_conf = f"{pred.rf.confidence:.1%}" if pred else "N/A"

    # DT Box
    y_before = pdf.get_y()
    pdf.set_fill_color(248, 250, 252)
    pdf.set_draw_color(226, 232, 240)
    pdf.set_line_width(0.3)
    pdf.rect(10, y_before, 92, 18, "DF")
    pdf.set_xy(14, y_before + 3)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(40, 5, f"Prediction: {dt_pred}", ln=0)
    pdf.cell(40, 5, f"Confidence: {dt_conf}", ln=1)
    pdf.set_x(14)
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.cell(80, 4.5, "Single CART tree with explainable rule splits", ln=0)

    # RF Box
    pdf.rect(108, y_before, 92, 18, "DF")
    pdf.set_xy(112, y_before + 3)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(40, 5, f"Prediction: {rf_pred}", ln=0)
    pdf.cell(40, 5, f"Confidence: {rf_conf}", ln=1)
    pdf.set_x(112)
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.cell(80, 4.5, "150-tree bagging ensemble with variance reduction", ln=1)
    pdf.ln(8)

    # 2. Parsed URL Anatomy
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "2. Parsed URL Structural Anatomy", ln=1)

    parsed = report.parsed_components or {}
    pdf.set_fill_color(248, 250, 252)
    pdf.set_draw_color(226, 232, 240)
    pdf.rect(10, pdf.get_y(), 190, 16, "DF")

    curr_y = pdf.get_y() + 2
    pdf.set_xy(14, curr_y)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(18, 4, "Scheme:", ln=0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(24, 4, str(parsed.get("scheme", "N/A")), ln=0)

    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(18, 4, "Hostname:", ln=0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(60, 4, str(parsed.get("hostname", "N/A"))[:35], ln=0)

    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(12, 4, "Port:", ln=0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(20, 4, str(parsed.get("port", "Standard (80/443)")), ln=1)

    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(18, 4, "Path:", ln=0)
    pdf.set_font("Helvetica", "", 8)
    path_str = str(parsed.get("path", "/"))[:45]
    pdf.cell(65, 4, path_str if path_str else "/", ln=0)

    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(24, 4, "Query Present:", ln=0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(20, 4, "Yes" if parsed.get("has_query") else "No", ln=0)

    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(26, 4, "Fragment Present:", ln=0)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(15, 4, "Yes" if parsed.get("has_fragment") else "No", ln=1)
    pdf.ln(5)

    # 3. Canonical 18-Dimensional Feature Table
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "3. Extracted Canonical URL Features (18 Dimensions)", ln=1)

    # Table Header
    pdf.set_fill_color(30, 41, 59)  # Dark slate
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(12, 5, "#", border=1, fill=True, align="C", ln=0)
    pdf.cell(55, 5, "Feature Identifier", border=1, fill=True, ln=0)
    pdf.cell(25, 5, "Extracted Value", border=1, fill=True, align="C", ln=0)
    pdf.cell(98, 5, "Cybersecurity Interpretation", border=1, fill=True, ln=1)

    feat_dict = report.features_dict or {}
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(30, 41, 59)

    interpretations = {
        "url_length": "Overall URL character length; long strings obscure real destinations.",
        "hostname_length": "Domain character count; phishers use bloated spoof names.",
        "path_length": "Directory path length; deep paths often house phishing scripts.",
        "query_length": "Query string character count; tokens frequently carried here.",
        "count_dots": "Dot frequency; multiple dots indicate excessive subdomain nesting.",
        "count_hyphens": "Hyphen count; frequently used in brand typosquatting lures.",
        "count_at": "Userinfo @ symbol; tricks browsers into redirecting to attacker host.",
        "count_question": "Query delimiter count.",
        "count_equal": "Parameter assignment delimiter count.",
        "count_ampersand": "Parameter concatenation delimiter count.",
        "count_percent": "Percent-encoding markers; used to obscure malicious URLs.",
        "count_digits": "Numerical digit count; IP literals or hexadecimal identifiers.",
        "count_subdomains": "Subdomain hierarchy depth relative to base domain.",
        "is_ip_address": "Binary check for raw IPv4/IPv6 host instead of domain name.",
        "is_https": "Protocol indicator (note: HTTPS does not guarantee legitimacy).",
        "is_shortener": "Known URL shortener service check (e.g. bit.ly, tinyurl).",
        "has_suspicious_keyword": "Presence of sensitive keywords (login, verify, bank, account).",
        "has_unusual_port": "Non-standard port indicator outside standard 80 or 443."
    }

    row_idx = 1
    for key, val in feat_dict.items():
        bg_fill = (row_idx % 2 == 0)
        pdf.set_fill_color(248, 250, 252) if bg_fill else pdf.set_fill_color(255, 255, 255)

        val_str = str(val)
        if isinstance(val, (int, float)):
            val_str = str(int(val)) if val == int(val) else f"{val:.2f}"

        interp = interpretations.get(key, "Extracted structural lexical feature.")
        pdf.cell(12, 4.5, str(row_idx), border=1, fill=True, align="C", ln=0)
        pdf.cell(55, 4.5, key, border=1, fill=True, ln=0)
        pdf.cell(25, 4.5, val_str, border=1, fill=True, align="C", ln=0)
        pdf.cell(98, 4.5, interp, border=1, fill=True, ln=1)
        row_idx += 1

    pdf.ln(4)

    # 4. Academic & Operational Disclaimer
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 5, "4. Scope & Technical Honesty Disclaimer", ln=1)

    pdf.set_font("Helvetica", "I", 7.5)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(
        0,
        3.8,
        "PhishGuard AI analyzes website URLs strictly using static structural and lexical characteristics. "
        "The application never makes HTTP or DNS connections to the submitted URL, never downloads DOM trees, "
        "and never executes client-side scripts. All outputs are probabilistic estimates generated by trained "
        "supervised machine learning models (Decision Tree and Random Forest) and must not be interpreted as an "
        "absolute certificate of website safety or safety guarantee."
    )

    # Return raw PDF bytes
    return bytes(pdf.output())
