"""Comprehensive runtime diagnostic and verification script for PhishGuard AI.

Verifies:
1. Environment packages (NumPy 1.26.4, PyArrow 17.0.0 compatibility).
2. pandas DataFrame creation & Arrow serialization (preventing st.dataframe runtime errors).
3. URL scanning, Decision Tree & Random Forest predictions.
4. PDF Security Intelligence report generation via fpdf2.
5. Emulates execution flow of all 5 Streamlit navigation pages.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def test_environment_and_pyarrow():
    print("=" * 60)
    print("1. Checking Environment & PyArrow Compatibility")
    print("=" * 60)
    import numpy as np
    import pandas as pd
    import pyarrow as pa
    import pyarrow.compute as pc
    
    print(f"NumPy version:   {np.__version__}")
    print(f"Pandas version:  {pd.__version__}")
    print(f"PyArrow version: {pa.__version__}")
    
    assert np.__version__.startswith("1.26"), f"Expected NumPy 1.26.x, got {np.__version__}"
    assert pa.__version__.startswith("17."), f"Expected PyArrow 17.x, got {pa.__version__}"

    # Test pyarrow table serialization from pandas (underlying st.dataframe mechanism)
    summary_rows = [
        {
            "Evaluation Metric": "Test Accuracy",
            "Decision Tree (DT)": "96.8%",
            "Random Forest (RF)": "100.0%",
            "Cybersecurity Significance": "Overall proportion of correct classifications."
        },
        {
            "Evaluation Metric": "Macro Precision",
            "Decision Tree (DT)": "0.9706",
            "Random Forest (RF)": "1.0000",
            "Cybersecurity Significance": "Minimizes false alarms."
        }
    ]
    df = pd.DataFrame(summary_rows)
    table = pa.Table.from_pandas(df)
    print(f"PyArrow Table successfully constructed from DataFrame: {table.shape}")
    print("PyArrow <-> NumPy compatibility VERIFIED!")


def test_pages_logic():
    print("\n" + "=" * 60)
    print("2. Verifying Logic Across All 5 Navigation Pages")
    print("=" * 60)
    import pandas as pd
    from src.phishguard.services.url_analyzer import analyze_url
    from src.phishguard.services.report_generator import generate_scan_pdf_report
    from src.phishguard.models.evaluate import load_evaluation_results
    from src.phishguard.models.train import load_model_artifacts

    # Home / URL Analyzer test
    test_url = "https://www.google.com"
    print(f"Testing URL scanning on '{test_url}'...")
    rep = analyze_url(test_url)
    assert rep.is_valid, "URL should be valid"
    assert rep.prediction_result is not None, "Prediction result must be present"
    print(f"  - Final Prediction: {rep.prediction_result.final_prediction_name}")
    print(f"  - DT Prediction:    {rep.prediction_result.dt.prediction_name}")
    print(f"  - RF Prediction:    {rep.prediction_result.rf.prediction_name}")

    # Section 1: URL Analysis features logic
    feats = rep.features_dict
    assert len(feats) == 18, f"Expected 18 features, got {len(feats)}"
    print(f"  - Extracted 18 features successfully.")

    # Section 2: Analysis Process DataFrame logic (Line 183 of pages/2_Analysis_Process.py)
    df_feat_summary = pd.DataFrame([
        {"Feature": k, "Extracted Value": v} for k, v in feats.items()
    ])
    assert not df_feat_summary.empty, "Feature summary DataFrame must not be empty"
    print(f"  - Analysis Process DataFrame generated: {df_feat_summary.shape}")

    # Section 3: Model Comparison evaluation results logic (Line 116 of pages/3_Model_Comparison.py)
    eval_data = load_evaluation_results()
    assert eval_data is not None, "Evaluation results must be present"
    dt_metrics = eval_data.get("decision_tree", {})
    rf_metrics = eval_data.get("random_forest", {})
    print(f"  - DT Test Accuracy: {dt_metrics.get('accuracy'):.1%}")
    print(f"  - RF Test Accuracy: {rf_metrics.get('accuracy'):.1%}")

    # Section 4: About Project artifacts
    dt_pipe, rf_pipe, metadata = load_model_artifacts()
    assert dt_pipe is not None and rf_pipe is not None, "Models must load"
    print(f"  - Model pipelines and metadata loaded successfully.")

    # PDF Report generation
    print("Testing PDF report generation...")
    pdf_bytes = generate_scan_pdf_report(rep)
    assert isinstance(pdf_bytes, bytes) and len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")
    print(f"  - PDF generated successfully ({len(pdf_bytes)} bytes).")


if __name__ == "__main__":
    test_environment_and_pyarrow()
    test_pages_logic()
    print("\n" + "=" * 60)
    print("ALL RUNTIME CHECKS PASSED SUCCESSFULLY!")
    print("=" * 60)

