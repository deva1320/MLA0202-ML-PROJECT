"""PhishGuard AI - Home & URL Scanner Application Entrypoint.

Title: Phishing Website Detection Using URL-Based Feature Extraction
with Decision Tree and Random Forest Algorithms.
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

from config import THEME_COLORS
from src.phishguard.utils.ui_helpers import (
    apply_custom_styles,
    init_session_state,
    render_sidebar
)
from src.phishguard.services.url_analyzer import analyze_url
from src.phishguard.models.evaluate import load_evaluation_results

st.set_page_config(
    page_title="PhishGuard AI | URL Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

init_session_state()
apply_custom_styles()
render_sidebar()

# Hero Header
st.markdown(
    """
    <div class="hero-box">
        <div class="hero-tagline">Detect Phishing. Browse Safely.</div>
        <div class="hero-title">PhishGuard AI</div>
        <div style="font-weight: 600; color: #0EA5E9; font-size: 1.05rem; margin-bottom: 8px;">
            Phishing Website Detection Using URL-Based Feature Extraction with Decision Tree and Random Forest Algorithms
        </div>
        <div class="hero-subtitle">
            A browser-based cybersecurity machine learning <strong>Web Application</strong> developed for Fundamentals of Machine Learning.
            Evaluates website URLs using 18 lexical and structural features without ever visiting, crawling,
            or executing the destination webpage. Dual supervised classifiers (Decision Tree &amp; Random Forest)
            deliver instant, explainable risk assessments directly through your web browser.
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# Sample URL presets for instant demonstration
PRESET_SAMPLES = {
    "-- Choose a demo URL to test --": "",
    "Legitimate: Google Search": "https://www.google.com/search?q=machine+learning+tutorial",
    "Legitimate: Wikipedia Article": "https://en.wikipedia.org/wiki/Phishing",
    "Legitimate: GitHub Repository": "https://github.com/scikit-learn/scikit-learn",
    "Legitimate: Amazon Portal": "https://www.amazon.com/gp/bestsellers",
    "Phishing: IP-Based Credential Harvester": "http://192.168.1.105/webscr/login.php?cmd=login_submit",
    "Phishing: Hyphenated Apple ID Verification": "http://apple-id-verify-account.support-service.net/auth/",
    "Phishing: Multi-Subdomain Bank Spoofing": "http://login.verification.secure.banking.paypal.com.fraudulent-host.org/webscr",
    "Phishing: Userinfo @ Redirection Spoof": "http://legit-service.com@attacker-site.com/steal-login?user=victim",
    "Phishing: Obfuscated Shortener Lure": "http://bit.ly/secure-paypal-login-verify",
    "Phishing: Non-Standard Port Attack": "http://45.142.214.88:8080/secure-update/account-verify/"
}

# Input Section
input_col, preset_col = st.columns([1.5, 1.0])

with preset_col:
    selected_sample = st.selectbox("Quick Demo Samples:", list(PRESET_SAMPLES.keys()))
    sample_text = PRESET_SAMPLES[selected_sample]

with input_col:
    url_input = st.text_input(
        "Enter Website URL to Inspect:",
        value=sample_text if sample_text else st.session_state.get("active_url", ""),
        placeholder="e.g. paypal-security-update.com/login.php or https://example.com",
        help="Input a domain or full URL. The URL is parsed lexically and will never be visited."
    )

check_btn = st.button("🔍 Check URL Safety", use_container_width=True)

if check_btn or (url_input and url_input != st.session_state.get("active_url")):
    st.session_state["active_url"] = url_input

    with st.spinner("Analyzing URL structure and running supervised classifiers..."):
        report = analyze_url(url_input)
        st.session_state["active_report"] = report

        # Record in session history
        if report.is_valid and report.prediction_result:
            st.session_state["scan_history"].insert(0, {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "url": report.normalized_url,
                "prediction": report.prediction_result.final_prediction_name,
                "confidence": f"{report.prediction_result.final_confidence:.1%}",
                "model": report.prediction_result.selected_model
            })

# Render Active Report
report = st.session_state.get("active_report")

if report is not None:
    st.markdown("---")

    if not report.is_valid:
        st.error(f"⚠️ Validation Error: {report.error_message}")
    else:
        if report.warning_message:
            st.info(report.warning_message)

        pred = report.prediction_result
        is_phish = (pred.final_prediction_name == "Phishing")

        # Top Result Banner
        status_badge_class = "badge-phish" if is_phish else "badge-safe"
        icon = "🚨" if is_phish else "✅"
        badge_text = "POTENTIAL PHISHING DETECTED" if is_phish else "LIKELY LEGITIMATE"

        st.markdown(
            f"""
            <div class="security-card" style="border-left: 6px solid {'#EF4444' if is_phish else '#10B981'};">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                    <div>
                        <div style="font-size:0.85rem; color:#94A3B8; text-transform:uppercase; font-weight:700;">CLASSIFICATION RESULT</div>
                        <h2 style="margin:4px 0; color:#FFFFFF;">{icon} {badge_text}</h2>
                        <div style="font-size:0.95rem; color:#94A3B8;">Target URL: <code style="color:#0EA5E9;">{report.normalized_url}</code></div>
                    </div>
                    <div style="text-align:right;">
                        <span class="{status_badge_class}">{pred.final_prediction_name}</span>
                        <div style="font-size:0.85rem; color:#94A3B8; margin-top:6px;">Confidence: <strong>{pred.final_confidence:.1%}</strong></div>
                    </div>
                </div>
                <hr style="border-color: rgba(255,255,255,0.08); margin: 16px 0;">
                <p style="color:#F8FAFC; font-size:0.95rem; margin:0; line-height:1.5;">
                    {pred.summary_explanation}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Dual Classifier Breakdown
        st.markdown("### 🤖 Supervised Classifier Comparison")
        col_dt, col_rf = st.columns(2)

        with col_rf:
            rf = pred.rf
            rf_is_phish = (rf.prediction_name == "Phishing")
            st.markdown(
                f"""
                <div class="security-card">
                    <div style="font-size:0.8rem; color:#0EA5E9; font-weight:700; text-transform:uppercase;">PRIMARY MODEL 2 (RECOMMENDED)</div>
                    <h3 style="margin:6px 0;">Random Forest Classifier</h3>
                    <p style="margin:6px 0;">Prediction: <strong style="color:{'#EF4444' if rf_is_phish else '#10B981'};">{rf.prediction_name}</strong></p>
                    <p style="color:#94A3B8; font-size:0.88rem; margin:0;">
                        Confidence: <strong>{rf.confidence:.1%}</strong> | Latency: <strong>{rf.latency_ms:.2f} ms</strong>
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
            # Probability Bar Chart
            fig_rf = go.Figure(go.Bar(
                x=list(rf.probabilities.values()),
                y=list(rf.probabilities.keys()),
                orientation="h",
                marker_color=["#10B981" if k == "Legitimate" else "#EF4444" for k in rf.probabilities.keys()],
                text=[f"{v:.1%}" for v in rf.probabilities.values()],
                textposition="auto"
            ))
            fig_rf.update_layout(
                title=dict(text="RF Probability Distribution", font=dict(color="#F8FAFC", size=13)),
                paper_bgcolor="#131C31",
                plot_bgcolor="#0B1120",
                margin=dict(l=85, r=20, t=35, b=25),
                xaxis=dict(range=[0, 1.0], tickformat=".0%", tickfont=dict(color="#94A3B8")),
                yaxis=dict(tickfont=dict(color="#94A3B8")),
                height=180
            )
            st.plotly_chart(fig_rf, use_container_width=True)

        with col_dt:
            dt = pred.dt
            dt_is_phish = (dt.prediction_name == "Phishing")
            st.markdown(
                f"""
                <div class="security-card">
                    <div style="font-size:0.8rem; color:#14B8A6; font-weight:700; text-transform:uppercase;">PRIMARY MODEL 1</div>
                    <h3 style="margin:6px 0;">Decision Tree Classifier</h3>
                    <p style="margin:6px 0;">Prediction: <strong style="color:{'#EF4444' if dt_is_phish else '#10B981'};">{dt.prediction_name}</strong></p>
                    <p style="color:#94A3B8; font-size:0.88rem; margin:0;">
                        Confidence: <strong>{dt.confidence:.1%}</strong> | Latency: <strong>{dt.latency_ms:.2f} ms</strong>
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
            # Probability Bar Chart
            fig_dt = go.Figure(go.Bar(
                x=list(dt.probabilities.values()),
                y=list(dt.probabilities.keys()),
                orientation="h",
                marker_color=["#10B981" if k == "Legitimate" else "#EF4444" for k in dt.probabilities.keys()],
                text=[f"{v:.1%}" for v in dt.probabilities.values()],
                textposition="auto"
            ))
            fig_dt.update_layout(
                title=dict(text="Decision Tree Probability Distribution", font=dict(color="#F8FAFC", size=13)),
                paper_bgcolor="#131C31",
                plot_bgcolor="#0B1120",
                margin=dict(l=85, r=20, t=35, b=25),
                xaxis=dict(range=[0, 1.0], tickformat=".0%", tickfont=dict(color="#94A3B8")),
                yaxis=dict(tickfont=dict(color="#94A3B8")),
                height=180
            )
            st.plotly_chart(fig_dt, use_container_width=True)

        # High-Risk Indicators Overview
        st.markdown("### ⚠️ Key Structural Risk Indicators")
        if report.risk_indicators:
            for ind in report.risk_indicators:
                sev_color = "#EF4444" if ind.severity == "High" else "#F59E0B" if ind.severity == "Medium" else "#10B981" if ind.severity == "Neutral" else "#94A3B8"
                st.markdown(
                    f"""
                    <div class="security-card" style="padding:14px 18px; margin-bottom:10px; border-left: 4px solid {sev_color};">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong style="color:#F8FAFC; font-size:0.95rem;">{ind.display_title}: <code>{ind.value}</code></strong>
                            <span class="badge-neutral" style="color:{sev_color}; border-color:{sev_color};">{ind.severity} Severity</span>
                        </div>
                        <p style="color:#94A3B8; font-size:0.88rem; margin:6px 0 0 0; line-height:1.4;">
                            {ind.explanation}
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.info("No anomalous lexical or structural risk indicators detected.")

        st.caption(f"🛡️ {report.disclaimer}")

st.markdown("---")

# Session Scan History
st.markdown("### 📜 Session Scan History")
history = st.session_state.get("scan_history", [])

if history:
    df_hist = pd.DataFrame(history)
    st.dataframe(df_hist, use_container_width=True, hide_index=True)
    if st.button("🗑️ Clear Scan History"):
        st.session_state["scan_history"] = []
        st.rerun()
else:
    st.caption("No URLs scanned during this active session yet.")

