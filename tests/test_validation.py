"""Unit tests for URL input validation and normalization."""

import pytest

from src.phishguard.utils.validation import validate_and_normalize_url, MAX_URL_LENGTH


def test_valid_https_url():
    is_valid, norm, err, warn = validate_and_normalize_url("https://www.google.com")
    assert is_valid is True
    assert norm == "https://www.google.com"
    assert err == ""


def test_url_without_scheme_auto_normalized():
    is_valid, norm, err, warn = validate_and_normalize_url("example.com/login")
    assert is_valid is True
    assert norm == "https://example.com/login"
    assert "Notice" in warn


def test_empty_input_rejected():
    is_valid, norm, err, warn = validate_and_normalize_url("")
    assert is_valid is False
    assert "valid website URL" in err


def test_whitespace_only_rejected():
    is_valid, norm, err, warn = validate_and_normalize_url("   \n\t  ")
    assert is_valid is False


def test_excessively_long_url_rejected():
    long_url = "https://example.com/" + "a" * (MAX_URL_LENGTH + 10)
    is_valid, norm, err, warn = validate_and_normalize_url(long_url)
    assert is_valid is False
    assert "exceeds maximum" in err


def test_unprintable_control_characters_rejected():
    bad_url = "https://example.com/\x00\x08test"
    is_valid, norm, err, warn = validate_and_normalize_url(bad_url)
    assert is_valid is False
    assert "control characters" in err


def test_url_with_ipv4_host():
    is_valid, norm, err, warn = validate_and_normalize_url("http://192.168.1.1/admin")
    assert is_valid is True
    assert norm == "http://192.168.1.1/admin"


def test_url_with_port():
    is_valid, norm, err, warn = validate_and_normalize_url("http://example.com:8080/portal")
    assert is_valid is True
    assert norm == "http://example.com:8080/portal"
