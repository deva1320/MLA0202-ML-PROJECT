"""Unit tests for URL prediction and security analysis service."""

import numpy as np
import pytest

from src.phishguard.models.predict import predict_url, DualModelPredictionResult
from src.phishguard.services.url_analyzer import analyze_url, URLAnalysisReport
from src.phishguard.features.url_features import extract_url_features


def test_predict_url_output_schema():
    """Verifies output structure of dual prediction function."""
    vec, _ = extract_url_features("https://www.google.com")
    res = predict_url(vec)

    assert isinstance(res, DualModelPredictionResult)
    assert res.dt.prediction_name in ("Legitimate", "Phishing")
    assert res.rf.prediction_name in ("Legitimate", "Phishing")
    assert 0.0 <= res.dt.confidence <= 1.0
    assert 0.0 <= res.rf.confidence <= 1.0
    assert isinstance(res.consensus, bool)
    assert res.final_prediction_name in ("Legitimate", "Phishing")


def test_invalid_dimension_raises_error():
    """Ensures input with wrong feature count is rejected."""
    wrong_vec = np.zeros(10, dtype=np.float32)
    with pytest.raises(ValueError, match="dimension"):
        predict_url(wrong_vec)


def test_end_to_end_analyze_url_legitimate():
    """Tests analysis of a standard legitimate URL."""
    report = analyze_url("https://www.wikipedia.org")
    assert isinstance(report, URLAnalysisReport)
    assert report.is_valid is True
    assert report.prediction_result is not None
    assert report.prediction_result.final_prediction_name == "Legitimate"
    assert len(report.risk_indicators) > 0


def test_end_to_end_analyze_url_phishing():
    """Tests analysis of an IP-based phishing lure."""
    report = analyze_url("http://192.168.1.100/webscr/login.php?verify=1")
    assert report.is_valid is True
    assert report.prediction_result.final_prediction_name == "Phishing"
    
    # Check that IP address risk indicator was triggered
    feat_names = [ind.feature_name for ind in report.risk_indicators]
    assert "is_ip_address" in feat_names
    assert "has_suspicious_keyword" in feat_names

