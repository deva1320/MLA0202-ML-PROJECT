"""Unit tests for Decision Tree and Random Forest training pipelines."""

import pandas as pd
import numpy as np
import pytest

from config import FEATURE_CONFIG
from src.phishguard.models.train import (
    create_decision_tree_pipeline,
    create_random_forest_pipeline,
    train_classifiers,
    load_model_artifacts
)


def test_pipeline_construction():
    """Ensures scikit-learn pipelines contain StandardScaler and the correct classifier."""
    dt_pipe = create_decision_tree_pipeline()
    assert "scaler" in dt_pipe.named_steps
    assert "classifier" in dt_pipe.named_steps
    assert dt_pipe.named_steps["classifier"].__class__.__name__ == "DecisionTreeClassifier"

    rf_pipe = create_random_forest_pipeline()
    assert "scaler" in rf_pipe.named_steps
    assert "classifier" in rf_pipe.named_steps
    assert rf_pipe.named_steps["classifier"].__class__.__name__ == "RandomForestClassifier"


def test_training_and_artifacts_loading():
    """Verifies that trained models are serialized and reloadable."""
    dt_pipe, rf_pipe, metadata = load_model_artifacts()
    
    assert dt_pipe is not None
    assert rf_pipe is not None
    assert "decision_tree" in metadata
    assert "random_forest" in metadata
    assert len(metadata["feature_names"]) == 18
    assert len(metadata["decision_tree"]["feature_importances"]) == 18
    assert len(metadata["random_forest"]["feature_importances"]) == 18

