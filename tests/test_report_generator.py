"""Unit tests for PDF scan report generator."""

import pytest
from src.phishguard.services.url_analyzer import analyze_url
from src.phishguard.services.report_generator import generate_scan_pdf_report


def test_generate_pdf_legitimate_url():
    """Verifies that a valid PDF is generated for a legitimate URL."""
    report = analyze_url("https://www.google.com")
    pdf_bytes = generate_scan_pdf_report(report)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    # PDF files start with %PDF
    assert pdf_bytes.startswith(b"%PDF")


def test_generate_pdf_phishing_url():
    """Verifies that a valid PDF is generated for a phishing URL."""
    report = analyze_url("http://192.168.1.105/webscr/login.php?cmd=login_submit")
    pdf_bytes = generate_scan_pdf_report(report)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")

