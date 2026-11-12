"""Model evaluation script for PhishGuard AI.

Evaluates trained Decision Tree and Random Forest classifiers on the held-out test split,
computes precision, recall, F1, confusion matrices, and latency metrics,
and saves results to artifacts/evaluation_results.json.
"""

import sys
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import PROCESSED_DATA_DIR, ML_CONFIG, FEATURE_CONFIG
from src.phishguard.data.prepare_dataset import prepare_url_dataset
from src.phishguard.models.train import load_model_artifacts
from src.phishguard.models.evaluate import evaluate_models


def main():
    print("=" * 60)
    print("PhishGuard AI - Held-out Test Set Evaluation")
    print("=" * 60)

    dataset_path = PROCESSED_DATA_DIR / "features_dataset.csv"
    if not dataset_path.exists():
        print(f"Features dataset not found. Running prepare_url_dataset...")
        prepare_url_dataset()

    df = pd.read_csv(dataset_path)

    # Identical deterministic split
    train_df, test_df = train_test_split(
        df,
        test_size=ML_CONFIG.test_size,
        random_state=ML_CONFIG.random_state,
        stratify=df["label"]
    )

    print(f"Loaded {len(test_df)} held-out test samples (20% test split).")
    print("Loading saved trained model pipelines...")

    try:
        dt_pipe, rf_pipe, metadata = load_model_artifacts()
    except Exception as e:
        print(f"Error loading artifacts: {e}")
        print("Please run: python scripts/train_models.py first.")
        sys.exit(1)

    results = evaluate_models(
        X_test=test_df[FEATURE_CONFIG.feature_names],
        y_test=test_df["label"],
        dt_pipeline=dt_pipe,
        rf_pipeline=rf_pipe
    )

    dt_m = results["decision_tree"]
    rf_m = results["random_forest"]

    print("\n" + "=" * 60)
    print("HELD-OUT TEST SET EVALUATION BENCHMARKS")
    print("=" * 60)
    print(f"{'Metric':<28} {'Decision Tree (DT)':<22} {'Random Forest (RF)':<22}")
    print("-" * 72)
    print(f"{'Accuracy':<28} {dt_m['accuracy']:<22.4f} {rf_m['accuracy']:<22.4f}")
    print(f"{'Macro Precision':<28} {dt_m['macro_precision']:<22.4f} {rf_m['macro_precision']:<22.4f}")
    print(f"{'Macro Recall':<28} {dt_m['macro_recall']:<22.4f} {rf_m['macro_recall']:<22.4f}")
    print(f"{'Macro F1-Score':<28} {dt_m['macro_f1']:<22.4f} {rf_m['macro_f1']:<22.4f}")
    print(f"{'Inference Latency (ms/sample)':<28} {dt_m['inference_latency_ms_per_sample']:<22.4f} {rf_m['inference_latency_ms_per_sample']:<22.4f}")

    print("\nPer-Class Metrics on Held-out Test Data:")
    print("--- Legitimate (0) ---")
    print(f"  DT: Precision={dt_m['per_class']['Legitimate']['precision']:.4f}, Recall={dt_m['per_class']['Legitimate']['recall']:.4f}, F1={dt_m['per_class']['Legitimate']['f1']:.4f}")
    print(f"  RF: Precision={rf_m['per_class']['Legitimate']['precision']:.4f}, Recall={rf_m['per_class']['Legitimate']['recall']:.4f}, F1={rf_m['per_class']['Legitimate']['f1']:.4f}")
    
    print("--- Phishing (1) ---")
    print(f"  DT: Precision={dt_m['per_class']['Phishing']['precision']:.4f}, Recall={dt_m['per_class']['Phishing']['recall']:.4f}, F1={dt_m['per_class']['Phishing']['f1']:.4f}")
    print(f"  RF: Precision={rf_m['per_class']['Phishing']['precision']:.4f}, Recall={rf_m['per_class']['Phishing']['recall']:.4f}, F1={rf_m['per_class']['Phishing']['f1']:.4f}")

    print(f"\nRecommended Model: {results['recommended_model']}")
    print(f"Reason: {results['selection_reason']}")
    print("\nEvaluation artifacts saved to artifacts/evaluation_results.json")
    print("=" * 60)


if __name__ == "__main__":
    main()
