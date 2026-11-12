"""PhishGuard AI - Web Application Entrypoint & Home Page.

Title: Phishing Website Detection Using URL-Based Feature Extraction
with Decision Tree and Random Forest Algorithms.

Navigation Structure:
1. Home (this page: URL Scanner, Dual Predictions, Report Download)
2. URL Analysis (pages/1_URL_Analysis.py)
3. Analysis Process (pages/2_Analysis_Process.py)
4. Model Comparison (pages/3_Model_Comparison.py)
5. About Project (pages/4_About_Project.py)
"""

import sys
from pathlib import Path
from datetime import datetime
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import FULL_PROJECT_TITLE, PROJECT_NAME, TAGLINE, THEME_COLORS
from src.phishguard.utils.ui_helpers import (
    apply_custom_styles,
    init_session_state,
    render_sidebar
)
from src.phishguard.services.url_analyzer import analyze_url
from src.phishguard.services.report_generator import generate_scan_pdf_report


def render_home():
    """Renders the Home page in exact sequence specified by Section 3."""
    apply_custom_styles()
    render_sidebar()

    # 1. Compact PhishGuard AI header and exact project title
    st.markdown(
        f"""
        <div class="hero-box" style="padding:22px 26px; margin-bottom:18px;">
            <div class="hero-tagline">{TAGLINE}</div>
            <div class="hero-title" style="font-size:1.85rem; margin-bottom:4px;">{PROJECT_NAME}</div>
            <div style="font-weight: 600; color: #0EA5E9; font-size: 1.0rem; margin-bottom: 6px;">
                {FULL_PROJECT_TITLE}
            </div>
            <div class="hero-subtitle" style="font-size:0.88rem; color:#94A3B8; margin-bottom:0;">
                Fundamentals of Machine Learning — Supervised Binary Classification with Decision Tree & Random Forest.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 2. One short sentence explaining the purpose
    st.markdown(
        "<div style='font-size:0.95rem; color:#E2E8F0; margin-bottom:16px;'>"
        "PhishGuard AI evaluates website URLs using 18 static lexical features to detect potential phishing threats "
        "without ever contacting, crawling, or downloading the destination website."
        "</div>",
        unsafe_allow_html=True
    )

    # Sample demo presets (clearly labeled for demonstration)
    PRESET_SAMPLES = {
        "-- Choose a demo URL to test --": "",
        "Legitimate Demo: Google Search (Safe query parameters)": "https://www.google.com/search?q=machine+learning+tutorial",
        "Legitimate Demo: Wikipedia Article (Clean encyclopedic URL)": "https://en.wikipedia.org/wiki/Phishing",
        "Legitimate Demo: GitHub Repository (Standard repo path)": "https://github.com/scikit-learn/scikit-learn",
        "Legitimate Demo: Amazon Store (Standard e-commerce path)": "https://www.amazon.com/gp/bestsellers",
        "Phishing Demo: IP Literal Host (Evades domain filters)": "http://192.168.1.105/webscr/login.php?cmd=login_submit",
        "Phishing Demo: Hyphenated Apple Spoof (Typosquatting)": "http://apple-id-verify-account.support-service.net/auth/",
        "Phishing Demo: Subdomain Chaining (Hides base domain)": "http://login.verification.secure.banking.paypal.com.fraudulent-host.org/webscr",
        "Phishing Demo: Userinfo @ Spoof (Credential lure)": "http://legit-service.com@attacker-site.com/steal-login?user=victim",
        "Phishing Demo: URL Shortener Mask (Concealed destination)": "http://bit.ly/secure-paypal-login-verify",
        "Phishing Demo: Non-Standard Port (Rogue web server)": "http://45.142.214.88:8080/secure-update/account-verify/"
    }

    # 3. Website URL input field & 5. Quick demo selector
    c_input, c_preset = st.columns([1.6, 1.0])

    with c_preset:
        selected_sample = st.selectbox(
            "Demo Test URLs (Examples only):",
            list(PRESET_SAMPLES.keys()),
            help="Select a benchmark URL to test immediately without visiting any live servers."
        )
        sample_text = PRESET_SAMPLES[selected_sample]

    with c_input:
        current_input = sample_text if sample_text else st.session_state.get("active_url", "")
        url_input = st.text_input(
            "Website URL to Analyze:",
            value=current_input,
            placeholder="e.g. paypal-security-update.com/login.php or https://example.com",
            help="Enter a website URL or domain. Analyzed statically using in-memory lexical parsing only."
        )

    # 4. Check URL button
    check_btn = st.button("🔍 Check URL", use_container_width=True, type="primary")

    if check_btn or (url_input and url_input != st.session_state.get("active_url")):
        st.session_state["active_url"] = url_input

        with st.spinner("Extracting 18 lexical features and executing Decision Tree & Random Forest classifiers..."):
            report = analyze_url(url_input)
            st.session_state["active_report"] = report

            if report.is_valid and report.prediction_result:
                st.session_state["scan_history"].insert(0, {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "url": report.normalized_url,
                    "prediction": report.prediction_result.final_prediction_name,
                    "confidence": f"{report.prediction_result.final_confidence:.1%}",
                    "model": report.prediction_result.selected_model
                })

    report = st.session_state.get("active_report")

    if report is not None:
        st.markdown("---")

        if not report.is_valid:
            st.error(f"⚠️ Validation Error: {report.error_message}")
            return

        if report.warning_message:
            st.info(report.warning_message)

        pred = report.prediction_result
        if not pred:
            st.warning("⚠️ Prediction unavailable. Models may not be trained.")
            return

        is_phish = (pred.final_prediction_name == "Phishing")
        parsed = report.parsed_components or {}

        # 6. Visual summary of the completed analysis
        st.markdown("### 📋 Analysis Summary")
        s_col1, s_col2, s_col3, s_col4 = st.columns(4)
        with s_col1:
            st.metric("Input Status", "Valid URL String")
            st.caption(f"Length: {len(report.normalized_url)} chars")
        with s_col2:
            st.metric("Protocol Scheme", parsed.get("scheme", "N/A").upper())
            st.caption("Normalized for parsing")
        with s_col3:
            st.metric("Features Extracted", f"{len(report.features_dict)}/18 Features")
            st.caption("Zero network calls made")
        with s_col4:
            st.metric("Model Consensus", "Agreed" if pred.consensus else "Disagreement")
            st.caption("DT vs RF agreement check")

        # 7. Decision Tree prediction card & 8. Random Forest prediction card
        st.markdown("### 🤖 Supervised Classifier Predictions")
        dt_col, rf_col = st.columns(2)

        # DT Card
        with dt_col:
            dt_is_phish = (pred.dt.prediction_name == "Phishing")
            dt_badge = "POTENTIAL PHISHING" if dt_is_phish else "LIKELY LEGITIMATE"
            dt_border = "#EF4444" if dt_is_phish else "#10B981"
            st.markdown(
                f"""
                <div class="security-card" style="border-top: 4px solid {dt_border}; padding:16px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.8rem; color:#14B8A6; font-weight:700; text-transform:uppercase;">MODEL 1</span>
                        <span style="font-size:0.75rem; color:{dt_border}; border:1px solid {dt_border}; padding:2px 8px; border-radius:10px; font-weight:700;">
                            {dt_badge}
                        </span>
                    </div>
                    <h3 style="margin:6px 0 2px 0; color:#F8FAFC;">Decision Tree Classifier</h3>
                    <p style="color:#94A3B8; font-size:0.85rem; margin:0 0 10px 0;">Rule-based CART algorithm with explainable if-then paths.</p>
                    <div style="font-size:1.15rem; font-weight:700; color:{dt_border}; margin-bottom:4px;">
                        Prediction: {pred.dt.prediction_name}
                    </div>
                    <div style="font-size:0.85rem; color:#CBD5E1;">
                        Model Estimate: <strong>{pred.dt.confidence:.1%}</strong> | Latency: <strong>{pred.dt.latency_ms:.2f} ms</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # RF Card
        with rf_col:
            rf_is_phish = (pred.rf.prediction_name == "Phishing")
            rf_badge = "POTENTIAL PHISHING" if rf_is_phish else "LIKELY LEGITIMATE"
            rf_border = "#EF4444" if rf_is_phish else "#10B981"
            st.markdown(
                f"""
                <div class="security-card" style="border-top: 4px solid {rf_border}; padding:16px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.8rem; color:#0EA5E9; font-weight:700; text-transform:uppercase;">MODEL 2 (RECOMMENDED)</span>
                        <span style="font-size:0.75rem; color:{rf_border}; border:1px solid {rf_border}; padding:2px 8px; border-radius:10px; font-weight:700;">
                            {rf_badge}
                        </span>
                    </div>
                    <h3 style="margin:6px 0 2px 0; color:#F8FAFC;">Random Forest Classifier</h3>
                    <p style="color:#94A3B8; font-size:0.85rem; margin:0 0 10px 0;">150-tree bagging ensemble reducing single-tree variance.</p>
                    <div style="font-size:1.15rem; font-weight:700; color:{rf_border}; margin-bottom:4px;">
                        Prediction: {pred.rf.prediction_name}
                    </div>
                    <div style="font-size:0.85rem; color:#CBD5E1;">
                        Model Estimate: <strong>{pred.rf.confidence:.1%}</strong> | Latency: <strong>{pred.rf.latency_ms:.2f} ms</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # 9. Final classification result
        final_label = "POTENTIAL PHISHING" if is_phish else "LIKELY LEGITIMATE"
        final_color = "#EF4444" if is_phish else "#10B981"
        agreement_note = (
            "✅ Model Consensus: Both Decision Tree and Random Forest reached identical conclusions."
            if pred.consensus else
            "⚠️ Model Disagreement: Classifiers produced differing outputs. Defaulting to Random Forest due to ensemble variance reduction."
        )

        st.markdown(
            f"""
            <div class="security-card" style="border-left: 6px solid {final_color}; margin-top:16px; padding:18px 22px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                    <div>
                        <div style="font-size:0.8rem; color:#94A3B8; text-transform:uppercase; font-weight:700;">FINAL CLASSIFICATION VERDICT</div>
                        <h2 style="margin:4px 0; color:{final_color}; font-size:1.75rem;">
                            {'🚨' if is_phish else '🛡️'} {final_label}
                        </h2>
                        <div style="font-size:0.9rem; color:#CBD5E1; margin-top:4px;">
                            {agreement_note}
                        </div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-size:0.8rem; color:#94A3B8;">Selected Primary Model</div>
                        <div style="font-size:1.05rem; font-weight:700; color:#0EA5E9;">{pred.selected_model}</div>
                        <div style="font-size:0.85rem; color:#CBD5E1; margin-top:4px;">Estimated Confidence: <strong>{pred.final_confidence:.1%}</strong></div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 10. Download Scan Report action (Real PDF generation)
        st.markdown("### 📄 Export Security Intelligence Report")
        try:
            pdf_bytes = generate_scan_pdf_report(report)
            safe_filename = f"PhishGuard_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            st.download_button(
                label="📥 Download Scan Report (PDF)",
                data=pdf_bytes,
                file_name=safe_filename,
                mime="application/pdf",
                help="Generates an audit-ready cybersecurity PDF report from the actual scan data."
            )
        except Exception as e:
            st.warning(f"Unable to generate PDF report: {e}")

        # 11. Small safety disclaimer
        st.caption(
            "🛡️ **Safety Disclaimer:** “This prediction is based on URL characteristics only. "
            "It is not a guarantee of website safety.”"
        )


# Setup multi-page navigation using Streamlit modern routing
st.set_page_config(
    page_title="PhishGuard AI | Home",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

init_session_state()

home_page = st.Page(render_home, title="Home", icon="🏠", default=True)
url_analysis_page = st.Page("pages/1_URL_Analysis.py", title="URL Analysis", icon="🔬")
analysis_process_page = st.Page("pages/2_Analysis_Process.py", title="Analysis Process", icon="⚙️")
model_comparison_page = st.Page("pages/3_Model_Comparison.py", title="Model Comparison", icon="📊")
about_project_page = st.Page("pages/4_About_Project.py", title="About Project", icon="📖")

pg = st.navigation([home_page, url_analysis_page, analysis_process_page, model_comparison_page, about_project_page])
pg.run()
