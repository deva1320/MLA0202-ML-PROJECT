"""Canonical URL-based feature extractor for PhishGuard AI.

Extracts an 18-dimensional numerical feature vector purely through lexical and structural
analysis of the URL string. Strictly zero external network requests, crawling, or DNS lookups.
"""

from typing import Dict, List, Tuple
from urllib.parse import urlparse
import ipaddress
import re
import numpy as np

from config import (
    FEATURE_CONFIG,
    KNOWN_URL_SHORTENERS,
    SUSPICIOUS_KEYWORDS
)
from src.phishguard.utils.validation import validate_and_normalize_url


def is_ip_host(hostname: str) -> int:
    """Checks whether the hostname is an IPv4 or IPv6 numerical address."""
    if not hostname:
        return 0
    clean_host = hostname.strip()
    # Handle bracketed IPv6 literals e.g. [2001:db8::1] or [2001:db8::1]:8080
    if clean_host.startswith("["):
        end_bracket = clean_host.find("]")
        if end_bracket != -1:
            clean_host = clean_host[1:end_bracket]
    elif ":" in clean_host and clean_host.count(":") == 1:
        # IPv4 with port e.g. 192.168.1.1:8080
        clean_host = clean_host.split(":")[0]

    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        return 0


def is_shortener_domain(hostname: str) -> int:
    """Checks whether domain belongs to a known URL shortening provider."""
    if not hostname:
        return 0
    host_lower = hostname.lower()
    for s in KNOWN_URL_SHORTENERS:
        if host_lower == s or host_lower.endswith(f".{s}"):
            return 1
    return 0


def count_subdomain_levels(hostname: str) -> int:
    """Calculates the number of subdomain hierarchy levels.
    
    Example:
        - example.com -> 0 subdomains
        - secure.paypal.com -> 1 subdomain ('secure')
        - login.verify.bank.com -> 2 subdomains ('login', 'verify')
    """
    if not hostname or is_ip_host(hostname):
        return 0
    parts = hostname.split(".")
    # If standard domain with ccTLD (e.g. .co.uk), compensate slightly
    if len(parts) <= 2:
        return 0
    return max(0, len(parts) - 2)


def check_suspicious_keywords(url_string: str) -> int:
    """Checks for presence of sensitive phishing tokens in URL (lowercase match)."""
    url_lower = url_string.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            return 1
    return 0


def get_canonical_feature_names() -> List[str]:
    """Returns the ordered list of 18 canonical feature names."""
    return FEATURE_CONFIG.feature_names


def extract_url_features(url_string: str) -> Tuple[np.ndarray, Dict[str, float]]:
    """Extracts the canonical 18-dimensional numerical feature vector from a URL.
    
    Args:
        url_string: Website URL string (with or without scheme).
        
    Returns:
        (feature_vector, feature_dict):
            feature_vector: 1D numpy array of shape (18,), dtype float32.
            feature_dict: Ordered dictionary mapping feature names to their numeric values.
    """
    is_valid, norm_url, err_msg, _ = validate_and_normalize_url(url_string)
    if not is_valid:
        # Fallback for malformed strings
        norm_url = url_string if url_string else ""

    try:
        parsed = urlparse(norm_url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        port = parsed.port
    except Exception:
        scheme = ""
        hostname = ""
        path = ""
        query = ""
        port = None

    features: Dict[str, float] = {}

    # 1. Structural Length Features
    features["url_length"] = float(len(norm_url))
    features["hostname_length"] = float(len(hostname))
    features["path_length"] = float(len(path))
    features["query_length"] = float(len(query))

    # 2. Punctuation & Delimiter Counts
    features["count_dots"] = float(norm_url.count("."))
    features["count_hyphens"] = float(norm_url.count("-"))
    features["count_at"] = float(norm_url.count("@"))
    features["count_question"] = float(norm_url.count("?"))
    features["count_equal"] = float(norm_url.count("="))
    features["count_ampersand"] = float(norm_url.count("&"))
    features["count_percent"] = float(norm_url.count("%"))

    # 3. Digits & Obfuscation
    features["count_digits"] = float(sum(1 for c in norm_url if c.isdigit()))
    features["count_subdomains"] = float(count_subdomain_levels(hostname))

    # 4. Security Indicators
    features["is_ip_address"] = float(is_ip_host(hostname))
    features["is_https"] = float(1 if scheme == "https" else 0)
    features["is_shortener"] = float(is_shortener_domain(hostname))
    features["has_suspicious_keyword"] = float(check_suspicious_keywords(norm_url))

    # 5. Unusual Port
    # Standard web ports are None (default), 80, 443
    if port is not None and port not in (80, 443):
        features["has_unusual_port"] = 1.0
    else:
        features["has_unusual_port"] = 0.0

    # Ensure stable ordering matching FEATURE_CONFIG.feature_names
    ordered_names = FEATURE_CONFIG.feature_names
    vector_list: List[float] = []

    for name in ordered_names:
        val = features.get(name, 0.0)
        # Ensure finite
        if not np.isfinite(val):
            val = 0.0
        vector_list.append(float(val))

    feature_vector = np.array(vector_list, dtype=np.float32)

    return feature_vector, features
