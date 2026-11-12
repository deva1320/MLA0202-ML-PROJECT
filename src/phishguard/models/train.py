"""Model training module for Decision Tree and Random Forest classifiers.

Fits both models on identical training splits, computes cross-validation benchmarks,
and persists serialized pipelines and training metadata to artifacts/.
"""

from datetime import datetime
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
import joblib
import pandas as pd
import numpy as np

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score

from config import ML_CONFIG, FEATURE_CONFIG, ARTIFACTS_DIR, LABEL_TO_NAME


class ModelArtifactError(Exception):
    """Raised when model artifacts cannot be loaded or are missing."""
    pass


def create_decision_tree_pipeline() -> Pipeline:
    """Creates a Decision Tree pipeline."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", DecisionTreeClassifier(
            max_depth=ML_CONFIG.dt_max_depth,
            min_samples_split=ML_CONFIG.dt_min_samples_split,
            min_samples_leaf=ML_CONFIG.dt_min_samples_leaf,
            criterion=ML_CONFIG.dt_criterion,
            random_state=ML_CONFIG.random_state
        ))
    ])


def create_random_forest_pipeline() -> Pipeline:
    """Creates a Random Forest pipeline."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=ML_CONFIG.rf_n_estimators,
            max_depth=ML_CONFIG.rf_max_depth,
            min_samples_split=ML_CONFIG.rf_min_samples_split,
            min_samples_leaf=ML_CONFIG.rf_min_samples_leaf,
            criterion=ML_CONFIG.rf_criterion,
            random_state=ML_CONFIG.random_state,
            n_jobs=-1
        ))
    ])


def train_classifiers(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    feature_names: Optional[List[str]] = None
) -> Tuple[Pipeline, Pipeline, Dict[str, Any]]:
    """Trains Decision Tree and Random Forest classifiers on training data.
    
    Returns:
        (dt_pipeline, rf_pipeline, metadata_dict)
    """
    if feature_names is None:
        feature_names = FEATURE_CONFIG.feature_names

    X_train_matrix = X_train[feature_names].values.astype(np.float32)
    y_train_vec = y_train.values.astype(int)

    cv = StratifiedKFold(n_splits=ML_CONFIG.cv_folds, shuffle=True, random_state=ML_CONFIG.random_state)

    # 1. Decision Tree Training & 5-Fold Cross Validation
    dt_pipeline = create_decision_tree_pipeline()
    t0_dt = time.time()
    dt_cv_scores = cross_val_score(dt_pipeline, X_train_matrix, y_train_vec, cv=cv, scoring="accuracy")
    dt_pipeline.fit(X_train_matrix, y_train_vec)
    dt_fit_time = time.time() - t0_dt

    # 2. Random Forest Training & 5-Fold Cross Validation
    rf_pipeline = create_random_forest_pipeline()
    t0_rf = time.time()
    rf_cv_scores = cross_val_score(rf_pipeline, X_train_matrix, y_train_vec, cv=cv, scoring="accuracy")
    rf_pipeline.fit(X_train_matrix, y_train_vec)
    rf_fit_time = time.time() - t0_rf

    # Extract Random Forest Gini Feature Importances
    rf_clf = rf_pipeline.named_steps["classifier"]
    rf_importances = rf_clf.feature_importances_
    sorted_rf_idx = np.argsort(rf_importances)[::-1]
    rf_top_features = [
        {"feature": feature_names[i], "importance": float(np.round(rf_importances[i], 4))}
        for i in sorted_rf_idx
    ]

    # Extract Decision Tree Feature Importances
    dt_clf = dt_pipeline.named_steps["classifier"]
    dt_importances = dt_clf.feature_importances_
    sorted_dt_idx = np.argsort(dt_importances)[::-1]
    dt_top_features = [
        {"feature": feature_names[i], "importance": float(np.round(dt_importances[i], 4))}
        for i in sorted_dt_idx
    ]

    metadata = {
        "project_title": "Phishing Website Detection Using URL-Based Feature Extraction with Decision Tree and Random Forest Algorithms",
        "training_timestamp": datetime.now().isoformat(),
        "train_samples": len(X_train),
        "feature_names": feature_names,
        "feature_count": len(feature_names),
        "classes": [LABEL_TO_NAME[0], LABEL_TO_NAME[1]],
        "decision_tree": {
            "algorithm": "Decision Tree Classifier (CART)",
            "max_depth": ML_CONFIG.dt_max_depth,
            "cv_accuracy_mean": float(np.round(dt_cv_scores.mean(), 4)),
            "cv_accuracy_std": float(np.round(dt_cv_scores.std(), 4)),
            "fit_time_seconds": float(np.round(dt_fit_time, 4)),
            "feature_importances": dt_top_features
        },
        "random_forest": {
            "algorithm": "Random Forest Classifier (Ensemble)",
            "n_estimators": ML_CONFIG.rf_n_estimators,
            "max_depth": ML_CONFIG.rf_max_depth,
            "cv_accuracy_mean": float(np.round(rf_cv_scores.mean(), 4)),
            "cv_accuracy_std": float(np.round(rf_cv_scores.std(), 4)),
            "fit_time_seconds": float(np.round(rf_fit_time, 4)),
            "feature_importances": rf_top_features
        }
    }

    # Persist Artifacts
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    dt_path = ARTIFACTS_DIR / ML_CONFIG.dt_artifact_name
    rf_path = ARTIFACTS_DIR / ML_CONFIG.rf_artifact_name
    meta_path = ARTIFACTS_DIR / ML_CONFIG.metadata_artifact_name

    joblib.dump(dt_pipeline, dt_path)
    joblib.dump(rf_pipeline, rf_path)

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return dt_pipeline, rf_pipeline, metadata


def load_model_artifacts() -> Tuple[Pipeline, Pipeline, Dict[str, Any]]:
    """Loads serialized Decision Tree, Random Forest, and training metadata."""
    dt_path = ARTIFACTS_DIR / ML_CONFIG.dt_artifact_name
    rf_path = ARTIFACTS_DIR / ML_CONFIG.rf_artifact_name
    meta_path = ARTIFACTS_DIR / ML_CONFIG.metadata_artifact_name

    if not dt_path.exists() or not rf_path.exists() or not meta_path.exists():
        raise ModelArtifactError(
            "Model artifacts missing from disk. Please run 'python scripts/train_models.py' first."
        )

    dt_pipeline = joblib.load(dt_path)
    rf_pipeline = joblib.load(rf_path)

    with open(meta_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    return dt_pipeline, rf_pipeline, metadata

