"""Streamlit UI styling, session state, and diagnostic helpers for PhishGuard AI."""

from pathlib import Path
import streamlit as st

from config import PROJECT_ROOT, THEME_COLORS
from src.phishguard.models.evaluate import load_evaluation_results


def apply_custom_styles():
    """Injects custom cybersecurity CSS into the active Streamlit page."""
    css_path = PROJECT_ROOT / "assets" / "styles" / "main.css"
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def init_session_state():
    """Initializes shared session state variables across pages."""
    defaults = {
        "active_url": "",
        "active_report": None,
        "scan_history": [],
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def render_sidebar():
    """Renders persistent diagnostics and navigation info in the sidebar."""
    with st.sidebar:
        st.markdown("### 🛡️ PhishGuard AI")
        st.markdown(
            "<div style='font-size:0.8rem; color:#0EA5E9; font-weight:700; text-transform:uppercase;'>"
            "Detect Phishing. Browse Safely.</div>",
            unsafe_allow_html=True
        )
        st.caption("Supervised ML: Decision Tree & Random Forest")
        st.divider()

        # Model readiness
        eval_data = load_evaluation_results()
        if eval_data:
            rf_acc = eval_data.get("random_forest", {}).get("accuracy", 0.0)
            dt_acc = eval_data.get("decision_tree", {}).get("accuracy", 0.0)
            st.markdown(
                f"**🟢 Classifiers Ready**  \n"
                f"- **RF Accuracy:** `{rf_acc:.1%}`  \n"
                f"- **DT Accuracy:** `{dt_acc:.1%}`  \n"
                f"- **Held-out Test:** `{eval_data.get('test_samples_count')} samples`"
            )
        else:
            st.markdown("🔴 **Models Status:** Not Trained")

        st.divider()

        # Active Scan Info
        report = st.session_state.get("active_report")
        if report and report.is_valid and report.prediction_result:
            pred_name = report.prediction_result.final_prediction_name
            color = "#10B981" if pred_name == "Legitimate" else "#EF4444"
            st.markdown(f"**Last Scanned URL:**  \n`{report.normalized_url[:30]}...`")
            st.markdown(
                f"**Status:** <span style='color:{color}; font-weight:700;'>{pred_name}</span>",
                unsafe_allow_html=True
            )
        else:
            st.markdown("*No URL scanned yet.*")

        st.divider()
        st.markdown(
            "<div style='font-size:0.75rem; color:#94A3B8; line-height:1.4;'>"
            "Zero network traffic: Submitted URLs are evaluated via lexical parsing only. "
            "No websites are crawled, fetched, or executed.</div>",
            unsafe_allow_html=True
        )
