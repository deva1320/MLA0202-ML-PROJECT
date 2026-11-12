"""PhishGuard AI - Section 2: Analysis Process Page.

Visual demonstration workflow showing the 6 connected stages of URL cybersecurity analysis:
1. URL Validation -> 2. URL Parsing -> 3. Feature Extraction -> 4. Decision Tree -> 5. Random Forest -> 6. Final Classification
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

st.set_page_config(
    page_title="Analysis Process | PhishGuard AI",
    page_icon="⚙️",
    layout="wide"
)

init_session_state()
apply_custom_styles()
render_sidebar()

st.title("⚙️ Analysis Process")
st.caption("Visual demonstration of the 6 sequential stages executed during URL risk evaluation.")

report = st.session_state.get("active_report")

if report is None:
    st.markdown(
        """
        <div class="security-card" style="text-align:center; padding: 40px 20px;">
            <div style="font-size: 2.5rem; margin-bottom: 10px;">⚙️</div>
            <h3 style="color:#F8FAFC; margin:0 0 8px 0;">No Active URL Analysis In Memory</h3>
            <p style="color:#94A3B8; max-width:550px; margin:0 auto 18px auto; font-size:0.95rem;">
                To view the interactive 6-stage machine learning pipeline, please submit a website address on the 
                <strong>Home</strong> page and click <strong>Check URL</strong>.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    pred = report.prediction_result
    parsed = report.parsed_components or {}
    feats = report.features_dict or {}

    # Top Overview Bar
    st.markdown(
        f"""
        <div class="security-card" style="margin-bottom:20px; padding:16px 20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                <div>
                    <div style="font-size:0.8rem; color:#94A3B8; text-transform:uppercase; font-weight:700;">Active Pipeline Target</div>
                    <code style="font-size:1.05rem; color:#0EA5E9;">{report.normalized_url}</code>
                </div>
                <div>
                    <span style="background:#10B981; color:#FFFFFF; padding:4px 12px; border-radius:12px; font-size:0.85rem; font-weight:700;">
                        PIPELINE COMPLETED (6/6 STAGES)
                    </span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 6-Stage Timeline Stepper Cards
    st.markdown("### 🔄 Connected Pipeline Stages")
    
    stages_data = [
        {
            "num": 1,
            "title": "URL Validation",
            "icon": "🛡️",
            "status": "VALID" if report.is_valid else "INVALID",
            "status_color": "#10B981" if report.is_valid else "#EF4444",
            "summary": "Sanitized string, checked length bounds, and verified non-empty printable input.",
            "details": f"Target passed validation check with {len(report.normalized_url)} characters. No unprintable control characters detected."
        },
        {
            "num": 2,
            "title": "URL Parsing",
            "icon": "🧩",
            "status": "COMPLETED",
            "status_color": "#10B981",
            "summary": f"Decomposed into RFC 3986 components (Scheme: {parsed.get('scheme', 'N/A').upper()}, Host: {parsed.get('hostname', 'N/A')[:20]}).",
            "details": f"Extracted Scheme: '{parsed.get('scheme')}', Host: '{parsed.get('hostname')}', Port: '{parsed.get('port')}', Path: '{parsed.get('path')}'. Done statically in-memory (0 network connections)."
        },
        {
            "num": 3,
            "title": "Feature Extraction",
            "icon": "📐",
            "status": f"{len(feats)}/18 FEATURES",
            "status_color": "#10B981",
            "summary": "Computed canonical 18-dimensional feature vector matching trained model schema.",
            "details": f"Lengths computed (URL: {feats.get('url_length', 0)}, Domain: {feats.get('hostname_length', 0)}), Delimiters counted (Dots: {feats.get('count_dots', 0)}, Hyphens: {feats.get('count_hyphens', 0)}), Heuristics checked (IP: {feats.get('is_ip_address', 0)}, Shortener: {feats.get('is_shortener', 0)})."
        },
        {
            "num": 4,
            "title": "Decision Tree (CART)",
            "icon": "🌲",
            "status": pred.dt.prediction_name.upper() if pred else "N/A",
            "status_color": "#EF4444" if (pred and pred.dt.prediction_name == "Phishing") else "#10B981",
            "summary": f"Single CART tree classified URL with {pred.dt.confidence:.1%} confidence." if pred else "Model not run.",
            "details": f"Fitted Decision Tree evaluated feature split thresholds along its decision paths. Latency: {pred.dt.latency_ms:.2f} ms. Prediction: {pred.dt.prediction_name}." if pred else "N/A"
        },
        {
            "num": 5,
            "title": "Random Forest (RF)",
            "icon": "🌳",
            "status": pred.rf.prediction_name.upper() if pred else "N/A",
            "status_color": "#EF4444" if (pred and pred.rf.prediction_name == "Phishing") else "#10B981",
            "summary": f"150-tree bagging ensemble classified URL with {pred.rf.confidence:.1%} confidence." if pred else "Model not run.",
            "details": f"Random Forest aggregated 150 decorrelated decision tree votes across feature subspaces to minimize single-tree variance. Latency: {pred.rf.latency_ms:.2f} ms. Prediction: {pred.rf.prediction_name}." if pred else "N/A"
        },
        {
            "num": 6,
            "title": "Final Classification",
            "icon": "🎯",
            "status": pred.final_prediction_name.upper() if pred else "N/A",
            "status_color": "#EF4444" if (pred and pred.final_prediction_name == "Phishing") else "#10B981",
            "summary": f"Consensus achieved: Both DT and RF selected {pred.final_prediction_name}." if (pred and pred.consensus) else "Ensemble preference applied.",
            "details": f"Policy: Both models are presented transparently. Final classification defaults to Random Forest based on held-out test benchmarks. Model Consensus: {'Yes' if (pred and pred.consensus) else 'No (Disagreement)'}." if pred else "N/A"
        }
    ]

    # Render horizontal/grid cards for the 6 stages
    col_row1 = st.columns(3)
    col_row2 = st.columns(3)

    for idx, s in enumerate(stages_data):
        target_col = col_row1[idx] if idx < 3 else col_row2[idx - 3]
        with target_col:
            st.markdown(
                f"""
                <div class="security-card" style="margin-bottom:14px; padding:16px; border-top: 4px solid {s['status_color']}; height:240px; display:flex; flex-direction:column; justify-content:space-between;">
                    <div>
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-size:0.8rem; color:#94A3B8; font-weight:700;">STAGE {s['num']}</span>
                            <span style="font-size:0.75rem; color:{s['status_color']}; font-weight:700; border:1px solid {s['status_color']}; padding:2px 8px; border-radius:10px;">
                                {s['status']}
                            </span>
                        </div>
                        <h4 style="margin:2px 0 8px 0; color:#F8FAFC; font-size:1.05rem;">{s['icon']} {s['title']}</h4>
                        <p style="font-size:0.85rem; color:#CBD5E1; line-height:1.4; margin:0;">{s['summary']}</p>
                    </div>
                    <div style="font-size:0.75rem; color:#64748B; border-top: 1px solid rgba(255,255,255,0.06); padding-top:8px;">
                        {s['details'][:110]}...
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    # In-depth stage expandable accordion
    st.markdown("### 🔍 Technical Stage Breakdown")

    with st.expander("Stage 1 & 2: Input Sanitization & Static RFC 3986 Parsing"):
        st.markdown(
            f"""
            - **Original Input:** `{report.original_url}`
            - **Normalized Format:** `{report.normalized_url}`
            - **Validation Status:** `Valid ({'HTTPS' if parsed.get('scheme') == 'https' else 'HTTP'})`
            - **Lexical Host:** `{parsed.get('hostname')}`
            - **Port Specification:** `{parsed.get('port')}`
            - **Path String:** `{parsed.get('path')}`
            - **Network Safety:** Static client-side lexical extraction. No DNS resolution, no socket calls, zero HTTP handshakes.
            """
        )

    with st.expander("Stage 3: Feature Extraction (18 Canonical Dimensions)"):
        st.markdown("Features extracted deterministically from URL string:")
        df_feat_summary = pd.DataFrame([
            {"Feature": k, "Extracted Value": v} for k, v in feats.items()
        ])
        st.dataframe(df_feat_summary, use_container_width=True, hide_index=True)

    with st.expander("Stage 4 & 5: Dual Supervised Model Inferences (DT vs RF)"):
        st.markdown(
            f"""
            - **Decision Tree Classifier:**
              - Prediction: `{pred.dt.prediction_name}` (Label `{pred.dt.prediction_label}`)
              - Probability Distribution: `{pred.dt.probabilities}`
              - Latency: `{pred.dt.latency_ms:.2f} ms`
            - **Random Forest Classifier:**
              - Prediction: `{pred.rf.prediction_name}` (Label `{pred.rf.prediction_label}`)
              - Probability Distribution: `{pred.rf.probabilities}`
              - Latency: `{pred.rf.latency_ms:.2f} ms`
            """
        )

    with st.expander("Stage 6: Final Consensus & Selection Policy"):
        st.markdown(
            f"""
            - **Model Consensus:** `{'Models Agree' if pred.consensus else 'Disagreement'}`
            - **Selected Prediction:** `{pred.final_prediction_name.upper()}`
            - **Selection Rational:** `Random Forest selected as default classifier due to lower variance and higher generalization across held-out benchmark splits.`
            - **Model Confidence:** `{pred.final_confidence:.1%}`
            """
        )
