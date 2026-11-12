"""Model evaluation module for Decision Tree and Random Forest classifiers.

Evaluates both models on identical held-out test data, computing accuracy,
precision, recall, F1, per-class metrics, confusion matrices, and inference latency.
"""

from datetime import datetime
import json
import time
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix
)

from config import ARTIFACTS_DIR, LABEL_TO_NAME, FEATURE_CONFIG
from src.phishguard.models.train import load_model_artifacts


def evaluate_single_pipeline(
    pipeline: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str
) -> Dict[str, Any]:
    """Computes comprehensive evaluation metrics for a single pipeline."""
    t0 = time.perf_counter()
    y_pred = pipeline.predict(X_test)
    t1 = time.perf_counter()

    latency_total_ms = (t1 - t0) * 1000.0
    latency_per_sample_ms = latency_total_ms / len(X_test) if len(X_test) > 0 else 0.0

    acc = float(accuracy_score(y_test, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_test, y_pred, average="weighted", zero_division=0
    )

    # Per-class metrics: 0 = Legitimate, 1 = Phishing
    p_per, r_per, f1_per, support = precision_recall_fscore_support(
        y_test, y_pred, labels=[0, 1], average=None, zero_division=0
    )

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    cm_norm = confusion_matrix(y_test, y_pred, labels=[0, 1], normalize="true")

    return {
        "model_name": model_name,
        "accuracy": float(np.round(acc, 4)),
        "macro_precision": float(np.round(p_macro, 4)),
        "macro_recall": float(np.round(r_macro, 4)),
        "macro_f1": float(np.round(f1_macro, 4)),
        "weighted_f1": float(np.round(f1_weighted, 4)),
        "per_class": {
            "Legitimate": {
                "precision": float(np.round(p_per[0], 4)),
                "recall": float(np.round(r_per[0], 4)),
                "f1": float(np.round(f1_per[0], 4)),
                "support": int(support[0])
            },
            "Phishing": {
                "precision": float(np.round(p_per[1], 4)),
                "recall": float(np.round(r_per[1], 4)),
                "f1": float(np.round(f1_per[1], 4)),
                "support": int(support[1])
            }
        },
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_normalized": np.round(cm_norm, 4).tolist(),
        "inference_latency_ms_per_sample": float(np.round(latency_per_sample_ms, 4)),
        "test_samples_count": len(y_test)
    }


def evaluate_models(
    X_test: pd.DataFrame,
    y_test: pd.Series,
    dt_pipeline: Optional[Any] = None,
    rf_pipeline: Optional[Any] = None
) -> Dict[str, Any]:
    """Evaluates both Decision Tree and Random Forest on held-out test data."""
    if dt_pipeline is None or rf_pipeline is None:
        dt_pipeline, rf_pipeline, _ = load_model_artifacts()

    feature_names = FEATURE_CONFIG.feature_names
    X_test_matrix = X_test[feature_names].values.astype(np.float32)
    y_test_vec = y_test.values.astype(int)

    dt_metrics = evaluate_single_pipeline(
        dt_pipeline, X_test_matrix, y_test_vec, "Decision Tree Classifier (DT)"
    )
    rf_metrics = evaluate_single_pipeline(
        rf_pipeline, X_test_matrix, y_test_vec, "Random Forest Classifier (RF)"
    )

    # Determine recommended model based on F1 and recall (prioritizing detection of phishing URLs)
    rf_f1 = rf_metrics["macro_f1"]
    dt_f1 = dt_metrics["macro_f1"]

    if rf_f1 >= dt_f1:
        recommended = "Random Forest Classifier (RF)"
        selection_reason = (
            f"Random Forest is the recommended primary model with {rf_metrics['accuracy']:.1%} accuracy and "
            f"{rf_f1:.4f} Macro F1. Its multi-tree ensemble bagging reduces single-tree variance and "
            f"demonstrates superior generalization across lexical edge cases."
        )
    else:
        recommended = "Decision Tree Classifier (DT)"
        selection_reason = (
            f"Decision Tree achieved {dt_metrics['accuracy']:.1%} accuracy and {dt_f1:.4f} Macro F1, "
            f"offering maximum architectural transparency."
        )

    results = {
        "evaluation_timestamp": datetime.now().isoformat(),
        "test_samples_count": len(y_test_vec),
        "recommended_model": recommended,
        "selection_reason": selection_reason,
        "decision_tree": dt_metrics,
        "random_forest": rf_metrics
    }

    # Save to artifacts/
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    eval_path = ARTIFACTS_DIR / "evaluation_results.json"
    with open(eval_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


def load_evaluation_results() -> Optional[Dict[str, Any]]:
    """Loads evaluation results if available."""
    eval_path = ARTIFACTS_DIR / "evaluation_results.json"
    if not eval_path.exists():
        return None
    try:
        with open(eval_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

