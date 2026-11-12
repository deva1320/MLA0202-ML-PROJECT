"""Unit tests for canonical 18-dimensional URL feature extraction."""

import numpy as np
import pytest

from config import FEATURE_CONFIG
from src.phishguard.features.url_features import (
    extract_url_features,
    get_canonical_feature_names,
    is_ip_host,
    is_shortener_domain,
    count_subdomain_levels,
    check_suspicious_keywords
)


def test_canonical_feature_names_order():
    """Confirms feature names strictly match config and have 18 elements."""
    names = get_canonical_feature_names()
    assert len(names) == 18
    assert names == FEATURE_CONFIG.feature_names
    assert "url_length" in names
    assert "is_ip_address" in names
    assert "is_https" in names
    assert "is_shortener" in names
    assert "has_suspicious_keyword" in names


def test_feature_vector_shape_and_dtype():
    """Verifies output vector is shape (18,) float32 with no NaNs."""
    vec, feat_dict = extract_url_features("https://www.google.com/search?q=machine+learning")
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (18,)
    assert vec.dtype == np.float32
    assert len(feat_dict) == 18
    assert np.all(np.isfinite(vec))


def test_ip_address_detection():
    """Tests IPv4 and IPv6 detection."""
    assert is_ip_host("192.168.1.1") == 1
    assert is_ip_host("45.33.32.156") == 1
    assert is_ip_host("[2001:db8::1]") == 1
    assert is_ip_host("google.com") == 0
    assert is_ip_host("paypal.com") == 0


def test_shortener_detection():
    """Tests URL shortener identification."""
    assert is_shortener_domain("bit.ly") == 1
    assert is_shortener_domain("tinyurl.com") == 1
    assert is_shortener_domain("t.co") == 1
    assert is_shortener_domain("github.com") == 0


def test_subdomain_counting():
    """Tests subdomain depth levels."""
    assert count_subdomain_levels("example.com") == 0
    assert count_subdomain_levels("www.google.com") == 1
    assert count_subdomain_levels("login.secure.paypal.com") == 2


def test_suspicious_keywords():
    """Tests presence of credential harvesting keywords."""
    assert check_suspicious_keywords("http://fake.com/login.php") == 1
    assert check_suspicious_keywords("http://fake.com/verify-account") == 1
    assert check_suspicious_keywords("https://wikipedia.org/wiki/Algorithm") == 0


def test_url_with_at_symbol():
    """Verifies '@' symbol count extraction."""
    _, feats = extract_url_features("http://user@target.com/page")
    assert feats["count_at"] == 1.0


def test_url_with_unusual_port():
    """Verifies non-standard port detection."""
    _, feats_std = extract_url_features("https://example.com:443/test")
    assert feats_std["has_unusual_port"] == 0.0

    _, feats_custom = extract_url_features("http://192.168.1.100:8888/login")
    assert feats_custom["has_unusual_port"] == 1.0

