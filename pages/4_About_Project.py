"""PhishGuard AI - Section 4: About Project Page.

Concise, visual project overview, problem statement, objectives, dataset provenance,
algorithm descriptions, technology cards, methodology diagram, and operational scope boundaries.
"""

import sys
from pathlib import Path
import streamlit as st

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import FULL_PROJECT_TITLE, PROJECT_NAME, TAGLINE
from src.phishguard.utils.ui_helpers import (
    apply_custom_styles,
    init_session_state,
    render_sidebar
)

st.set_page_config(
    page_title="About Project | PhishGuard AI",
    page_icon="📖",
    layout="wide"
)

init_session_state()
apply_custom_styles()
render_sidebar()

st.title("📖 About PhishGuard AI")
st.caption(FULL_PROJECT_TITLE)

# 1. Project Overview & Problem Statement
c_ov1, c_ov2 = st.columns(2)

with c_ov1:
    st.markdown(
        f"""
        <div class="security-card" style="height:100%;">
            <h4 style="color:#0EA5E9; margin-top:0;">🎯 Project Overview</h4>
            <p style="color:#CBD5E1; font-size:0.92rem; line-height:1.5;">
                <strong>{PROJECT_NAME}</strong> is a browser-based machine learning cybersecurity web application 
                developed for <em>Fundamentals of Machine Learning</em>. It detects phishing websites exclusively 
                through <strong>static URL structural and lexical feature extraction</strong> without ever visiting, 
                crawling, or executing the target website.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

with c_ov2:
    st.markdown(
        """
        <div class="security-card" style="height:100%;">
            <h4 style="color:#14B8A6; margin-top:0;">🛡️ Problem Statement & Objective</h4>
            <p style="color:#CBD5E1; font-size:0.92rem; line-height:1.5;">
                Phishing campaigns exploit misleading URLs (typosquatting, IP hosts, subdomain chaining) to steal credentials. 
                Traditional blacklists fail against zero-day domains, while live web crawling poses security risks.
                <strong>Objective:</strong> Accurately classify URLs as Legitimate or Phishing using an 18-dimensional lexical feature schema 
                and two primary supervised classifiers: <strong>Decision Tree (DT)</strong> and <strong>Random Forest (RF)</strong>.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

# 2. Methodology Workflow Diagram
st.markdown("### 🔄 Methodology Workflow")
st.markdown(
    """
    ```mermaid
    flowchart LR
        A[Dataset Ingestion] --> B[Data Preparation & 80/20 Split]
        B --> C[18-Dim URL Feature Extraction]
        C --> D[Supervised Model Training]
        D --> E[Held-Out Model Evaluation]
        E --> F[In-Browser URL Prediction & PDF Report]
    ```
    """
)

# 3. Supervised Classifiers: Decision Tree vs. Random Forest
st.markdown("### 🤖 Supervised Machine Learning Algorithms")
alg_c1, alg_c2 = st.columns(2)

with alg_c1:
    st.markdown(
        """
        <div class="security-card" style="border-top:4px solid #14B8A6;">
            <div style="font-size:1.5rem; margin-bottom:4px;">🌲</div>
            <h4 style="color:#14B8A6; margin:0 0 6px 0;">Decision Tree Classifier (DT)</h4>
            <p style="color:#94A3B8; font-size:0.88rem; line-height:1.4;">
                A non-parametric model utilizing the CART (Classification and Regression Trees) formulation with Gini Impurity.
            </p>
            <ul style="color:#CBD5E1; font-size:0.85rem; padding-left:18px; line-height:1.5;">
                <li><strong>Interpretability:</strong> Transparent if-then decision paths suitable for security auditing.</li>
                <li><strong>Architecture:</strong> Single tree with max depth of 8 and Gini split criteria.</li>
                <li><strong>Limitation:</strong> Susceptible to high variance on complex lexical edge cases.</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True
    )

with alg_c2:
    st.markdown(
        """
        <div class="security-card" style="border-top:4px solid #0EA5E9;">
            <div style="font-size:1.5rem; margin-bottom:4px;">🌳</div>
            <h4 style="color:#0EA5E9; margin:0 0 6px 0;">Random Forest Classifier (RF)</h4>
            <p style="color:#94A3B8; font-size:0.88rem; line-height:1.4;">
                An ensemble of 150 decorrelated decision trees combining bootstrap aggregating (bagging) and random subspace projection.
            </p>
            <ul style="color:#CBD5E1; font-size:0.85rem; padding-left:18px; line-height:1.5;">
                <li><strong>Variance Reduction:</strong> Averages multiple trees to prevent single-tree overfitting.</li>
                <li><strong>Architecture:</strong> 150 estimators with Gini split criterion and feature bagging.</li>
                <li><strong>Output:</strong> Calibrated class probabilities and Gini feature importances.</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True
    )

# 4. Dataset Provenance
st.markdown("### 📚 Dataset Provenance & Integrity")
st.markdown(
    """
    <div class="security-card">
        <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:12px;">
            <div>
                <strong>Dataset:</strong> Benchmark URL Dataset (Ground-Truth Labeled)<br>
                <strong>Provenance:</strong> Synthesized from verified authentic web services and documented phishing attack signatures (derived from UCI PhiUSIIL / PhishTank benchmark formats).
            </div>
            <div>
                <strong>Total Records:</strong> 312 URLs (153 Legitimate, 159 Phishing)<br>
                <strong>Split Strategy:</strong> Stratified 80/20 train/test split (249 train, 63 held-out test)
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# 5. Technology Stack Cards
st.markdown("### 💻 Verified Technology Stack")
t_col1, t_col2, t_col3, t_col4 = st.columns(4)
with t_col1:
    st.markdown(
        """
        <div class="security-card" style="text-align:center; padding:12px;">
            <h4 style="color:#0EA5E9; margin:0;">Python 3.11</h4>
            <span style="font-size:0.75rem; color:#94A3B8;">Core Language</span>
        </div>
        """,
        unsafe_allow_html=True
    )
with t_col2:
    st.markdown(
        """
        <div class="security-card" style="text-align:center; padding:12px;">
            <h4 style="color:#10B981; margin:0;">Streamlit</h4>
            <span style="font-size:0.75rem; color:#94A3B8;">Web Application</span>
        </div>
        """,
        unsafe_allow_html=True
    )
with t_col3:
    st.markdown(
        """
        <div class="security-card" style="text-align:center; padding:12px;">
            <h4 style="color:#F59E0B; margin:0;">Scikit-learn</h4>
            <span style="font-size:0.75rem; color:#94A3B8;">CART & Random Forest</span>
        </div>
        """,
        unsafe_allow_html=True
    )
with t_col4:
    st.markdown(
        """
        <div class="security-card" style="text-align:center; padding:12px;">
            <h4 style="color:#8B5CF6; margin:0;">FPDF2 & Plotly</h4>
            <span style="font-size:0.75rem; color:#94A3B8;">PDF Reports & Visuals</span>
        </div>
        """,
        unsafe_allow_html=True
    )

# 6. Operational Scope & Limitations
st.markdown("---")
st.markdown(
    """
    <div class="security-card" style="border-left: 4px solid #EF4444;">
        <h4 style="color:#EF4444; margin-top:0;">⚠️ Operational Scope & Academic Boundaries</h4>
        <p style="color:#CBD5E1; font-size:0.9rem; line-height:1.5; margin:0;">
            “The application analyzes URL characteristics only. It does not inspect website content, verify ownership, or guarantee that a website is safe.”
        </p>
        <p style="color:#94A3B8; font-size:0.85rem; line-height:1.5; margin-top:8px;">
            PhishGuard AI evaluates structural indicators without visiting destination domains. 
            All classifications represent probabilistic machine-learning estimates and do not replace antivirus, 
            firewalls, or human discernment.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

