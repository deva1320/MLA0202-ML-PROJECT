"""PhishGuard AI - Section 1: URL Analysis Page.

Displays compact responsive cards of actual extracted structural and lexical features
from the URL entered on Home, along with parsed URL anatomical components.
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import FULL_PROJECT_TITLE, THEME_COLORS
from src.phishguard.utils.ui_helpers import (
    apply_custom_styles,
    init_session_state,
    render_sidebar
)

st.set_page_config(
    page_title="URL Analysis | PhishGuard AI",
    page_icon="🔬",
    layout="wide"
)

init_session_state()
apply_custom_styles()
render_sidebar()

# Header
st.title("🔬 URL Analysis")
st.caption("Deep-dive inspection of 18 static lexical and structural characteristics extracted from the target URL.")

report = st.session_state.get("active_report")

if report is None or not report.is_valid:
    st.markdown(
        """
        <div class="security-card" style="text-align:center; padding: 40px 20px;">
            <div style="font-size: 2.5rem; margin-bottom: 10px;">🔍</div>
            <h3 style="color:#F8FAFC; margin:0 0 8px 0;">No Active URL Scan Found</h3>
            <p style="color:#94A3B8; max-width:550px; margin:0 auto 18px auto; font-size:0.95rem;">
                To inspect extracted structural features and URL anatomy, please enter a website address on the 
                <strong>Home</strong> page and click <strong>Check URL</strong>.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    # URL Banner
    st.markdown(
        f"""
        <div class="security-card" style="margin-bottom:16px; padding:16px 20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                <div>
                    <div style="font-size:0.8rem; color:#94A3B8; text-transform:uppercase; font-weight:700;">Analyzed Target URL</div>
                    <code style="font-size:1.05rem; color:#0EA5E9;">{report.normalized_url}</code>
                </div>
                <div>
                    <span class="{'badge-phish' if report.prediction_result.final_prediction_name == 'Phishing' else 'badge-safe'}">
                        {report.prediction_result.final_prediction_name.upper()}
                    </span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 1. Parsed URL Anatomy Expandable Section
    parsed = report.parsed_components or {}
    with st.expander("🧩 Parsed URL Structural Anatomy (Safe Lexical Components)", expanded=True):
        st.markdown(
            "<div style='font-size:0.88rem; color:#94A3B8; margin-bottom:12px;'>"
            "The URL was partitioned into standard RFC 3986 components in-memory without contacting the destination server."
            "</div>",
            unsafe_allow_html=True
        )
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Protocol Scheme", parsed.get("scheme", "N/A").upper())
            st.caption("HTTPS encrypts transmission but does not guarantee authenticity.")
        with c2:
            st.metric("Target Hostname", parsed.get("hostname", "N/A")[:25])
            st.caption(f"Length: {len(parsed.get('hostname', ''))} characters")
        with c3:
            st.metric("Destination Port", parsed.get("port", "Standard (80/443)"))
            st.caption("Unusual non-standard ports indicate rogue hosting.")
        with c4:
            has_q = "Yes" if parsed.get("has_query") else "No"
            st.metric("Query Parameters", has_q)
            st.caption("Credential harvesting tokens often pass in queries.")

        c5, c6 = st.columns(2)
        with c5:
            st.markdown(f"**Path Segment:** `{(parsed.get('path') or '/')[:60]}`")
        with c6:
            st.markdown(f"**Fragment Anchor:** `{(parsed.get('fragment') or 'None')[:40]}`")

    st.markdown("### 📊 Extracted 18-Dimensional Feature Matrix")
    st.markdown(
        "<div style='font-size:0.88rem; color:#94A3B8; margin-bottom:16px;'>"
        "Restrained status indicators reflect individual lexical measurements. "
        "A single unusual metric is not proof of phishing; classification depends on the multivariate machine learning model."
        "</div>",
        unsafe_allow_html=True
    )

    feats = report.features_dict or {}

    # Define feature metadata: (key, title, icon, unit/desc, evaluate_status_fn)
    feature_specs = [
        ("url_length", "URL Length", "📏", "Total characters in the URL string",
         lambda v: ("Unusual indicator", "#F59E0B") if v > 85 else ("Normal indicator", "#10B981")),
        ("hostname_length", "Hostname Length", "🌐", "Character count of the domain name",
         lambda v: ("Unusual indicator", "#F59E0B") if v > 32 else ("Normal indicator", "#10B981")),
        ("path_length", "Path Length", "📂", "Character count of directory path segments",
         lambda v: ("Unusual indicator", "#F59E0B") if v > 45 else ("Normal indicator", "#10B981")),
        ("query_length", "Query Length", "❓", "Character count of parameter query string",
         lambda v: ("Unusual indicator", "#F59E0B") if v > 40 else ("Normal indicator", "#10B981")),
        ("count_dots", "Dot Count", "⚪", "Frequency of '.' characters in URL",
         lambda v: ("Unusual indicator", "#F59E0B") if v >= 4 else ("Normal indicator", "#10B981")),
        ("count_hyphens", "Hyphen Count", "➖", "Frequency of '-' characters (brand typosquatting)",
         lambda v: ("Unusual indicator", "#F59E0B") if v >= 2 else ("Normal indicator", "#10B981")),
        ("count_at", "Userinfo Symbol (@)", "📧", "Userinfo redirection marker in host string",
         lambda v: ("Unusual indicator", "#EF4444") if v > 0 else ("Not detected", "#64748B")),
        ("count_digits", "Digit Count", "🔢", "Numerical digit frequency throughout URL",
         lambda v: ("Unusual indicator", "#F59E0B") if v > 8 else ("Normal indicator", "#10B981")),
        ("count_subdomains", "Subdomain Depth", "🏢", "Hierarchy levels preceding base domain",
         lambda v: ("Unusual indicator", "#EF4444") if v >= 3 else ("Normal indicator", "#10B981")),
        ("is_ip_address", "Raw IP Literal", "💻", "Host is IPv4/IPv6 address instead of domain",
         lambda v: ("Unusual indicator", "#EF4444") if v == 1 else ("Not detected", "#64748B")),
        ("is_https", "HTTPS Protocol", "🔒", "Encrypted scheme (HTTPS ≠ legitimacy)",
         lambda v: ("Normal indicator", "#10B981") if v == 1 else ("Unusual indicator", "#F59E0B")),
        ("is_shortener", "URL Shortener", "✂️", "Matches known URL shortener service",
         lambda v: ("Unusual indicator", "#F59E0B") if v == 1 else ("Not detected", "#64748B")),
        ("has_suspicious_keyword", "Sensitive Keywords", "🔑", "Tokens: login, verify, banking, update",
         lambda v: ("Unusual indicator", "#EF4444") if v == 1 else ("Not detected", "#64748B")),
        ("has_unusual_port", "Unusual Port", "🚪", "Port outside standard HTTP(80) / HTTPS(443)",
         lambda v: ("Unusual indicator", "#EF4444") if v == 1 else ("Not detected", "#64748B")),
        ("count_percent", "Percent Obfuscation", "🔣", "Hex percent-encoding markers (%20, %2E)",
         lambda v: ("Unusual indicator", "#EF4444") if v > 0 else ("Not detected", "#64748B")),
        ("count_question", "Question Marks", "❔", "Query delimiter symbol count",
         lambda v: ("Normal indicator", "#10B981") if v <= 1 else ("Unusual indicator", "#F59E0B")),
        ("count_equal", "Equals Symbols", "🟰", "Parameter assignment symbol count",
         lambda v: ("Normal indicator", "#10B981") if v <= 3 else ("Unusual indicator", "#F59E0B")),
        ("count_ampersand", "Ampersand Symbols", "🔗", "Parameter concatenation symbol count",
         lambda v: ("Normal indicator", "#10B981") if v <= 3 else ("Unusual indicator", "#F59E0B")),
    ]

    # Render in responsive 3-column card grid
    grid_cols = st.columns(3)
    for idx, (f_key, f_title, f_icon, f_desc, f_eval) in enumerate(feature_specs):
        val = feats.get(f_key, 0)
        status_label, status_color = f_eval(val)

        col = grid_cols[idx % 3]
        val_display = int(val) if isinstance(val, (int, float)) and val == int(val) else f"{val}"
        if f_key.startswith("is_") or f_key.startswith("has_"):
            val_display = "Active (Yes)" if val == 1 else "Inactive (No)"

        with col:
            st.markdown(
                f"""
                <div class="security-card" style="margin-bottom:12px; padding:14px 16px; border-left: 3px solid {status_color};">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                        <span style="font-size:0.95rem; font-weight:600; color:#F8FAFC;">{f_icon} {f_title}</span>
                        <span style="font-size:0.75rem; font-weight:600; color:{status_color}; padding:2px 8px; border-radius:10px; background:rgba(255,255,255,0.04); border:1px solid {status_color};">
                            {status_label}
                        </span>
                    </div>
                    <div style="font-size:1.15rem; font-weight:700; color:#0EA5E9; margin:4px 0;">{val_display}</div>
                    <div style="font-size:0.78rem; color:#94A3B8; line-height:1.3;">{f_desc}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.markdown("---")
    st.info(
        "💡 **Academic Note:** Individual lexical features provide statistical signals, but phishing websites increasingly "
        "adopt legitimate infrastructure (e.g. valid HTTPS certificates, clean top-level domains). Both Decision Tree and "
        "Random Forest algorithms combine these 18 measurements into an ensemble decision boundary rather than relying on any single indicator."
    )
