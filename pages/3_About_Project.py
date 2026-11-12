"""PhishGuard AI - About Project Page.

Comprehensive academic and engineering documentation for Fundamentals of Machine Learning:
Problem statement, objectives, architecture, feature formulations, and ML algorithms.
"""

import sys
from pathlib import Path
import streamlit as st

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.phishguard.utils.ui_helpers import (
    apply_custom_styles,
    init_session_state,
    render_sidebar
)

st.set_page_config(page_title="About Project | PhishGuard AI", page_icon="📖", layout="wide")

init_session_state()
apply_custom_styles()
render_sidebar()

st.title("📖 About PhishGuard AI")
st.markdown(
    "### **Phishing Website Detection Using URL-Based Feature Extraction with Decision Tree and Random Forest Algorithms**"
)

tab1, tab2, tab3, tab4 = st.tabs([
    "🎯 Problem & Objectives",
    "🏗️ Architecture & Methodology",
    "🤖 Supervised Classifiers",
    "⚠️ Scope & Security Limits"
])

with tab1:
    st.markdown(
        """
        <div class="security-card">
            <h4 style="color:#0EA5E9; margin-top:0;">1. Problem Statement</h4>
            <p style="color:#94A3B8; font-size:0.95rem; line-height:1.6;">
                Phishing attacks remain one of the most prolific threats in cybersecurity, causing billions of dollars
                in annual fraud and credential theft. Traditional blacklist-based countermeasures fail against zero-day
                phishing campaigns that dynamically generate short-lived domains and ephemeral hostnames.
                Furthermore, dynamic website content inspection (crawling HTML, downloading DOM trees, rendering JavaScript)
                is computationally expensive, risks client-side code execution, and fails when attackers cloak pages
                against automated scanners. There is an urgent need for lightweight, fast, and secure client-side
                phishing detection based exclusively on static URL structural and lexical analysis.
            </p>
            <h4 style="color:#14B8A6; margin-top:16px;">2. Academic Aim & Objectives</h4>
            <ul style="color:#94A3B8; font-size:0.95rem; line-height:1.6;">
                <li><strong>Static Lexical Feature Engineering:</strong> Design and implement an 18-dimensional feature extractor that captures domain length, delimiter counts, subdomain depth, IP octets, and credential lures with 0 network calls.</li>
                <li><strong>Supervised Machine Learning Comparison:</strong> Train, optimize, and fairly benchmark exactly two primary supervised classifiers: <strong>Decision Tree Classifier (DT)</strong> and <strong>Random Forest Classifier (RF)</strong>.</li>
                <li><strong>Model Explainability:</strong> Provide transparent decision boundary insights via Decision Tree logic and Random Forest Gini feature importances.</li>
                <li><strong>Interactive Cybersecurity Dashboard:</strong> Deliver a clean, responsive Streamlit interface providing instant predictions, risk factor breakdowns, and held-out test benchmarks.</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True
    )

with tab2:
    st.markdown("### 🏗️ Methodology & System Workflow")
    
    st.markdown(
        """
        The PhishGuard AI processing pipeline operates sequentially as follows:
        1. **Input Normalization:** Sanitizes raw URL input, strips whitespace, guards against control characters, and applies scheme normalization for lexical parsing.
        2. **18-Dimensional Feature Extraction:** Computes lengths, delimiter frequencies, subdomain depth, IP host format, URL shortener matching, and sensitive keyword presence.
        3. **Standardized Pipeline Scaling:** Features are scaled using `StandardScaler` fitted strictly on training data.
        4. **Dual Supervised Inference:** The vector is passed independently into the Decision Tree and Random Forest models.
        5. **Risk Factor Synthesis:** Anomalous attributes are compiled into human-readable security risk cards.
        """
    )

    st.markdown("#### Canonical 18-Dimensional Feature Schema:")
    st.markdown(
        """
        | Index | Feature Identifier | Mathematical / Lexical Definition | Cybersecurity Significance |
        |---|---|---|---|
        | 1 | `url_length` | Total character count of normalized URL | Phishers often inflate URLs to obscure target domain |
        | 2 | `hostname_length` | Total character count of domain name | Excessively long hostnames indicate spoofing |
        | 3 | `path_length` | Character count of URL path component | Deep directory paths indicate redirection lures |
        | 4 | `query_length` | Character count of query string | Phishing parameters often pass encoded tokens |
        | 5 | `count_dots` | Total occurrences of `.` | Indicates excessive subdomain layering |
        | 6 | `count_hyphens` | Total occurrences of `-` | Used to mimic legitimate brands (e.g. `paypal-update`) |
        | 7 | `count_at` | Total occurrences of `@` | Browser userinfo spoofing indicator |
        | 8 | `count_question` | Total occurrences of `?` | Query parameter delimiter |
        | 9 | `count_equal` | Total occurrences of `=` | Parameter assignment frequency |
        | 10 | `count_ampersand` | Total occurrences of `&` | Parameter concatenation frequency |
        | 11 | `count_percent` | Total occurrences of `%` | Hex / percent-encoding obfuscation marker |
        | 12 | `count_digits` | Total numerical digits | IP octets or random hexadecimal hashes |
        | 13 | `count_subdomains` | Hostname dot count minus TLD baseline | Subdomain spoofing depth |
        | 14 | `is_ip_address` | Binary indicator (IPv4/IPv6 format) | Circumvents domain registration and DNS monitoring |
        | 15 | `is_https` | Binary indicator (HTTPS protocol) | Protocol indicator (clarifying HTTPS ≠ legitimacy) |
        | 16 | `is_shortener` | Binary indicator (known URL shortener) | Masks true destination |
        | 17 | `has_suspicious_keyword` | Binary indicator (e.g. login, verify) | Credential-harvesting lure tokens |
        | 18 | `has_unusual_port` | Binary indicator (port outside 80/443) | Rogue server indicator |
        """
    )

with tab3:
    st.markdown("### 🤖 Supervised Classification Algorithms")
    
    st.markdown(
        """
        <div class="security-card">
            <h4 style="color:#14B8A6; margin-top:0;">1. Decision Tree Classifier (DT)</h4>
            <p style="color:#94A3B8; font-size:0.95rem; line-height:1.6;">
                A non-parametric supervised learning algorithm utilizing the CART (Classification and Regression Trees) formulation.
                At each internal node, the feature and split threshold that maximizes Gini Impurity reduction is chosen:
            </p>
            <p style="text-align:center; color:#0EA5E9; font-family:'JetBrains Mono';">
                I_G(p) = 1 - Σ (p_i)^2
            </p>
            <p style="color:#94A3B8; font-size:0.95rem;">
                <strong>Strengths:</strong> Complete structural transparency, highly interpretable if-then decision rules, and fast inference.
            </p>

            <h4 style="color:#0EA5E9; margin-top:16px;">2. Random Forest Classifier (RF)</h4>
            <p style="color:#94A3B8; font-size:0.95rem; line-height:1.6;">
                An ensemble learning method constructing 150 decorrelated decision trees using bootstrap aggregating (bagging)
                and random feature subspace projection. The final prediction aggregates ensemble votes:
            </p>
            <p style="text-align:center; color:#0EA5E9; font-family:'JetBrains Mono';">
                y_hat = mode(T_1(x), T_2(x), ..., T_B(x))
            </p>
            <p style="color:#94A3B8; font-size:0.95rem;">
                <strong>Strengths:</strong> Dramatically reduces single-tree variance and overfitting, robust to non-linear feature interactions,
                and outputs calibrated class probabilities and Gini feature importances.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

with tab4:
    st.markdown("### ⚠️ Scope Boundaries & Academic Integrity")
    
    st.markdown(
        """
        <div class="security-card" style="border-left: 4px solid #EF4444;">
            <h4 style="color:#EF4444; margin-top:0;">Security & Operational Boundaries</h4>
            <ul style="color:#94A3B8; font-size:0.95rem; line-height:1.6;">
                <li><strong>No Network Fetching:</strong> PhishGuard AI never connects to, crawls, downloads, renders, or executes the submitted URL. All features are static and lexical.</li>
                <li><strong>Machine Learning Probability vs. Safety Guarantee:</strong> Predictions are statistical estimates based on historical URL patterns. The application does not replace antivirus software or commercial firewall protection.</li>
                <li><strong>No User Credential Logging:</strong> Submitted URLs are processed in memory and retained only within the temporary active browser session.</li>
                <li><strong>Technical Honesty:</strong> Evaluation metrics reflect true measured performance on held-out test splits. No metrics or predictions are hardcoded or fabricated.</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True
    )
