"""PhishGuard AI - URL Feature Analysis Page.

Displays full 18-dimensional lexical and structural feature breakdown
with cybersecurity descriptions and anomaly indicators.
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import FEATURE_CONFIG
from src.phishguard.utils.ui_helpers import (
    apply_custom_styles,
    init_session_state,
    render_sidebar
)

st.set_page_config(page_title="URL Feature Analysis | PhishGuard AI", page_icon="🔬", layout="wide")

init_session_state()
apply_custom_styles()
render_sidebar()

st.title("🔬 URL Feature Analysis")
st.markdown(
    "Examines the canonical 18-dimensional structural and lexical feature vector extracted from the analyzed URL. "
    "Features are strictly derived from URL parsing without ever connecting to the destination server."
)

report = st.session_state.get("active_report")

if report is None or not report.is_valid:
    st.info("No active URL has been analyzed yet! Please return to the **Home URL Scanner** to test a website.")
    if st.button("🛡️ Go to URL Scanner"):
        st.switch_page("app.py")
    st.stop()

st.markdown(f"**Target URL:** ` {report.normalized_url} `")

# Summary Metrics
c1, c2, c3, c4 = st.columns(4)
c1.metric("URL Length", f"{int(report.features_dict.get('url_length', 0))} chars")
c2.metric("Hostname Length", f"{int(report.features_dict.get('hostname_length', 0))} chars")
c3.metric("Dots Count", f"{int(report.features_dict.get('count_dots', 0))}")
c4.metric("Hyphens Count", f"{int(report.features_dict.get('count_hyphens', 0))}")

st.markdown("---")

st.markdown("### 📋 18-Dimensional Extracted Feature Schema")
st.caption("Each numerical feature maps directly to inputs fed into the Decision Tree and Random Forest pipelines.")

feature_descriptions = FEATURE_CONFIG.feature_descriptions
table_records = []

for feat_name in FEATURE_CONFIG.feature_names:
    val = report.features_dict.get(feat_name, 0.0)
    desc = feature_descriptions.get(feat_name, "Lexical metric")
    
    # Format representation
    if feat_name in ("is_ip_address", "is_https", "is_shortener", "has_suspicious_keyword", "has_unusual_port"):
        formatted_val = "Yes (1.0)" if val == 1.0 else "No (0.0)"
    else:
        formatted_val = str(int(val)) if val.is_integer() else f"{val:.2f}"

    table_records.append({
        "Feature Name": feat_name,
        "Extracted Value": formatted_val,
        "Cybersecurity Description & Rationale": desc
    })

df_features = pd.DataFrame(table_records)
st.dataframe(df_features, use_container_width=True, hide_index=True)

st.markdown("---")

# Security Guidance Callout
st.markdown(
    """
    <div class="security-card" style="border-left: 4px solid #14B8A6;">
        <h4 style="margin-top:0; color:#14B8A6;">Important Note on HTTPS & Security Indicators</h4>
        <p style="color:#94A3B8; font-size:0.92rem; line-height:1.6; margin:0;">
            • <strong>HTTPS does not guarantee safety:</strong> A green padlock simply signifies an encrypted channel. Phishing campaigns frequently acquire legitimate SSL/TLS certificates via automated certificate authorities (such as Let's Encrypt).<br>
            • <strong>Individual features are indicators, not proof:</strong> A long URL or a hyphenated domain is not inherently malicious by itself. Supervised classifiers evaluate multivariate feature interactions across the entire 18-dimensional space.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)
