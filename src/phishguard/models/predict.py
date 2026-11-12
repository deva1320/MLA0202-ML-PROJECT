"""Inference module for Decision Tree and Random Forest URL prediction."""

from dataclasses import dataclass
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from config import FEATURE_CONFIG, LABEL_TO_NAME
from src.phishguard.models.train import load_model_artifacts


@dataclass
class SingleModelPrediction:
    """Individual model prediction result."""
    model_name: str
    prediction_label: int      # 0 = Legitimate, 1 = Phishing
    prediction_name: str       # 'Legitimate' or 'Phishing'
    confidence: float          # Probability of predicted class
    probabilities: Dict[str, float]
    latency_ms: float


@dataclass
class DualModelPredictionResult:
    """Combined prediction result from both Decision Tree and Random Forest."""
    dt: SingleModelPrediction
    rf: SingleModelPrediction
    consensus: bool
    final_prediction_name: str
    final_confidence: float
    selected_model: str
    summary_explanation: str
    feature_vector: np.ndarray
    feature_names: List[str]


def predict_url(
    features: Union[np.ndarray, Dict[str, float]],
    models: Optional[Tuple[Any, Any, Dict]] = None
) -> DualModelPredictionResult:
    """Executes dual inference using Decision Tree and Random Forest pipelines.
    
    Args:
        features: 18-dim numpy array or feature dictionary.
        models: Optional preloaded (dt_pipeline, rf_pipeline, metadata) tuple.
    """
    if models is None:
        dt_pipeline, rf_pipeline, metadata = load_model_artifacts()
    else:
        dt_pipeline, rf_pipeline, metadata = models

    feature_names = FEATURE_CONFIG.feature_names
    total_dim = len(feature_names)

    # Format into 2D float32 array of shape (1, 18)
    if isinstance(features, dict):
        vec = [float(features.get(f, 0.0)) for f in feature_names]
        X = np.array([vec], dtype=np.float32)
    elif isinstance(features, np.ndarray):
        if features.ndim == 1:
            if len(features) != total_dim:
                raise ValueError(f"Feature vector dimension {len(features)} does not match {total_dim}.")
            X = features.reshape(1, -1).astype(np.float32)
        elif features.ndim == 2:
            if features.shape[1] != total_dim:
                raise ValueError(f"Feature matrix columns {features.shape[1]} does not match {total_dim}.")
            X = features.astype(np.float32)
        else:
            raise ValueError("Invalid feature array dimension.")
    else:
        raise ValueError(f"Unsupported features input type: {type(features)}")

    # 1. Decision Tree Prediction
    t0_dt = time.perf_counter()
    dt_pred = int(dt_pipeline.predict(X)[0])
    dt_probs = dt_pipeline.predict_proba(X)[0]
    t1_dt = time.perf_counter()
    dt_latency_ms = (t1_dt - t0_dt) * 1000.0

    dt_prob_dict = {
        LABEL_TO_NAME[0]: float(np.round(dt_probs[0], 4)),
        LABEL_TO_NAME[1]: float(np.round(dt_probs[1], 4))
    }

    dt_result = SingleModelPrediction(
        model_name="Decision Tree Classifier (DT)",
        prediction_label=dt_pred,
        prediction_name=LABEL_TO_NAME[dt_pred],
        confidence=float(np.round(dt_probs[dt_pred], 4)),
        probabilities=dt_prob_dict,
        latency_ms=round(dt_latency_ms, 3)
    )

    # 2. Random Forest Prediction
    t0_rf = time.perf_counter()
    rf_pred = int(rf_pipeline.predict(X)[0])
    rf_probs = rf_pipeline.predict_proba(X)[0]
    t1_rf = time.perf_counter()
    rf_latency_ms = (t1_rf - t0_rf) * 1000.0

    rf_prob_dict = {
        LABEL_TO_NAME[0]: float(np.round(rf_probs[0], 4)),
        LABEL_TO_NAME[1]: float(np.round(rf_probs[1], 4))
    }

    rf_result = SingleModelPrediction(
        model_name="Random Forest Classifier (RF)",
        prediction_label=rf_pred,
        prediction_name=LABEL_TO_NAME[rf_pred],
        confidence=float(np.round(rf_probs[rf_pred], 4)),
        probabilities=rf_prob_dict,
        latency_ms=round(rf_latency_ms, 3)
    )

    consensus = (dt_pred == rf_pred)

    # Final Decision Policy:
    # Random Forest is the validated primary model due to superior ensemble generalization.
    final_name = rf_result.prediction_name
    final_conf = rf_result.confidence
    selected_model = "Random Forest Classifier (RF)"

    if consensus:
        summary = (
            f"Consensus: Both Decision Tree and Random Forest classify this URL as '{final_name}' "
            f"(RF confidence: {rf_result.confidence:.1%}, DT confidence: {dt_result.confidence:.1%})."
        )
    else:
        summary = (
            f"Model Disagreement: Random Forest predicts '{rf_result.prediction_name}' ({rf_result.confidence:.1%}), "
            f"whereas Decision Tree predicts '{dt_result.prediction_name}' ({dt_result.confidence:.1%}). "
            f"The final assessment defaults to Random Forest based on held-out ensemble validation."
        )

    return DualModelPredictionResult(
        dt=dt_result,
        rf=rf_result,
        consensus=consensus,
        final_prediction_name=final_name,
        final_confidence=final_conf,
        selected_model=selected_model,
        summary_explanation=summary,
        feature_vector=X[0],
        feature_names=feature_names
    )

