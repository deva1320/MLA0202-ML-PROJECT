"""PhishGuard AI - Model Comparison Page.

Benchmarks Decision Tree and Random Forest classifiers on held-out test data:
Accuracy, Precision, Recall, F1-scores, Confusion Matrices, and Gini Feature Importances.
"""

import sys
from pathlib import Path
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import THEME_COLORS, FEATURE_CONFIG
from src.phishguard.utils.ui_helpers import (
    apply_custom_styles,
    init_session_state,
    render_sidebar
)
from src.phishguard.models.evaluate import load_evaluation_results
from src.phishguard.models.train import load_model_artifacts

st.set_page_config(page_title="Model Comparison | PhishGuard AI", page_icon="⚖️", layout="wide")

init_session_state()
apply_custom_styles()
render_sidebar()

st.title("⚖️ Supervised Model Comparison & Evaluation")
st.markdown(
    "Comparative performance evaluation between the two primary supervised classifiers: "
    "**Decision Tree Classifier (DT)** and **Random Forest Classifier (RF)**. "
    "All reported benchmarks reflect genuine evaluation on held-out test data."
)

eval_data = load_evaluation_results()

if eval_data is None:
    st.warning("Model evaluation benchmarks not found! Please run 'python scripts/evaluate_models.py' first.")
    st.stop()

dt_m = eval_data.get("decision_tree", {})
rf_m = eval_data.get("random_forest", {})
rec_model = eval_data.get("recommended_model", "Random Forest")

# KPI Metrics Overview
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("DT Test Accuracy", f"{dt_m.get('accuracy', 0.0):.1%}")
with col2:
    st.metric("RF Test Accuracy", f"{rf_m.get('accuracy', 0.0):.1%}")
with col3:
    st.metric("DT Test Recall (Phishing)", f"{dt_m.get('per_class', {}).get('Phishing', {}).get('recall', 0.0):.1%}")
with col4:
    st.metric("RF Test Recall (Phishing)", f"{rf_m.get('per_class', {}).get('Phishing', {}).get('recall', 0.0):.1%}")

# Selection Rationale Card
st.markdown(
    f"""
    <div class="security-card" style="border-left: 4px solid #0EA5E9; margin: 20px 0;">
        <h4 style="margin-top:0; color:#FFFFFF;">Selected Primary Model: {rec_model}</h4>
        <p style="color:#94A3B8; font-size:0.95rem; line-height:1.6; margin:0;">
            {eval_data.get('selection_reason', '')}
        </p>
        <div style="font-size:0.85rem; color:#0EA5E9; margin-top:8px;">
            Held-out Test Evaluation: <strong>{eval_data.get('test_samples_count')} samples</strong> | 
            RF Latency: <strong>{rf_m.get('inference_latency_ms_per_sample', 0.0):.3f} ms/sample</strong> | 
            DT Latency: <strong>{dt_m.get('inference_latency_ms_per_sample', 0.0):.3f} ms/sample</strong>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown("---")

# Metrics Comparison Table
st.markdown("### 📊 Benchmark Metrics Comparison")
metrics_table = [
    {"Metric": "Test Accuracy", "Decision Tree (DT)": f"{dt_m.get('accuracy', 0.0):.4f}", "Random Forest (RF)": f"{rf_m.get('accuracy', 0.0):.4f}", "Security Importance": "Overall correctness across all test samples."},
    {"Metric": "Macro Precision", "Decision Tree (DT)": f"{dt_m.get('macro_precision', 0.0):.4f}", "Random Forest (RF)": f"{rf_m.get('macro_precision', 0.0):.4f}", "Security Importance": "Minimizes false positives (blocking legitimate URLs)."},
    {"Metric": "Macro Recall", "Decision Tree (DT)": f"{dt_m.get('macro_recall', 0.0):.4f}", "Random Forest (RF)": f"{rf_m.get('macro_recall', 0.0):.4f}", "Security Importance": "Critical: Measures ability to catch malicious URLs."},
    {"Metric": "Macro F1-Score", "Decision Tree (DT)": f"{dt_m.get('macro_f1', 0.0):.4f}", "Random Forest (RF)": f"{rf_m.get('macro_f1', 0.0):.4f}", "Security Importance": "Harmonic mean balancing precision and recall."},
    {"Metric": "Inference Latency", "Decision Tree (DT)": f"{dt_m.get('inference_latency_ms_per_sample', 0.0):.3f} ms", "Random Forest (RF)": f"{rf_m.get('inference_latency_ms_per_sample', 0.0):.3f} ms", "Security Importance": "Speed required for real-time browser gateway scanning."}
]
st.dataframe(pd.DataFrame(metrics_table), use_container_width=True, hide_index=True)

# Cybersecurity Metric Explanation
st.markdown(
    """
    <div class="security-card" style="border-left: 4px solid #F59E0B; margin: 16px 0;">
        <h4 style="margin-top:0; color:#F59E0B;">Why High Recall is Paramount in Cybersecurity</h4>
        <p style="color:#94A3B8; font-size:0.9rem; line-height:1.5; margin:0;">
            In phishing website detection, a <strong>False Negative</strong> (missing an actual phishing link) is catastrophic: 
            a user enters credentials or financial details into an attacker's server. Conversely, a <strong>False Positive</strong> 
            (flagging a safe website) causes minor user inconvenience. Thus, classifiers must maximize Recall for the Phishing class.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown("---")

# Confusion Matrices
st.markdown("### 🔲 Normalized Confusion Matrices")
cm_col1, cm_col2 = st.columns(2)
classes = ["Legitimate", "Phishing"]

def plot_cm(cm_data, title, colorscale="Blues"):
    fig = go.Figure(data=go.Heatmap(
        z=cm_data,
        x=classes,
        y=classes,
        colorscale=colorscale,
        text=[[f"{val:.0%}" for val in row] for row in cm_data],
        texttemplate="%{text}",
        textfont=dict(color="#FFFFFF", size=14),
        colorbar=dict(title=dict(text="Ratio", font=dict(color="#94A3B8")))
    ))
    fig.update_layout(
        title=dict(text=title, font=dict(color="#F8FAFC", size=13)),
        paper_bgcolor="#131C31",
        plot_bgcolor="#0B1120",
        margin=dict(l=70, r=20, t=35, b=45),
        xaxis=dict(title="Predicted Class", tickfont=dict(color="#94A3B8")),
        yaxis=dict(title="Actual Ground Truth", tickfont=dict(color="#94A3B8"), autorange="reversed"),
        height=300
    )
    return fig

with cm_col1:
    cm_dt = dt_m.get("confusion_matrix_normalized", [[0, 0], [0, 0]])
    st.plotly_chart(plot_cm(cm_dt, "Decision Tree Confusion Matrix", "Teal"), use_container_width=True)

with cm_col2:
    cm_rf = rf_m.get("confusion_matrix_normalized", [[0, 0], [0, 0]])
    st.plotly_chart(plot_cm(cm_rf, "Random Forest Confusion Matrix", "Blues"), use_container_width=True)

st.markdown("---")

# Random Forest Feature Importance
try:
    _, _, metadata = load_model_artifacts()
    rf_feats = metadata.get("random_forest", {}).get("feature_importances", [])
    if rf_feats:
        st.markdown("### 🌲 Random Forest Feature Importances (Gini Impurity)")
        st.caption(
            "Indicates the normalized reduction in Gini node impurity contributed by each URL feature across all ensemble trees."
        )

        f_names = [f["feature"] for f in rf_feats[:12]][::-1]
        f_scores = [f["importance"] for f in rf_feats[:12]][::-1]

        fig_imp = go.Figure(go.Bar(
            x=f_scores,
            y=f_names,
            orientation="h",
            marker=dict(color="#0EA5E9"),
            text=[f"{v:.4f}" for v in f_scores],
            textposition="auto"
        ))
        fig_imp.update_layout(
            paper_bgcolor="#131C31",
            plot_bgcolor="#0B1120",
            margin=dict(l=150, r=20, t=25, b=25),
            xaxis=dict(title="Gini Impurity Importance", tickfont=dict(color="#94A3B8")),
            yaxis=dict(tickfont=dict(color="#94A3B8")),
            height=380
        )
        st.plotly_chart(fig_imp, use_container_width=True)
except Exception:
    pass
