"""End-to-end URL security analysis service.

Coordinates validation, 18-dim feature extraction, dual model inference,
and human-readable risk indicator synthesis.
"""

from datetime import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import numpy as np

from config import FEATURE_CONFIG
from src.phishguard.utils.validation import validate_and_normalize_url, URLValidationError
from src.phishguard.features.url_features import extract_url_features
from src.phishguard.models.predict import predict_url, DualModelPredictionResult


@dataclass
class RiskIndicator:
    """Explains an individual URL characteristic in plain language."""
    feature_name: str
    display_title: str
    value: Any
    severity: str  # 'High', 'Medium', 'Low', 'Neutral'
    explanation: str


@dataclass
class URLAnalysisReport:
    """Comprehensive analysis report for a submitted URL."""
    original_url: str
    normalized_url: str
    is_valid: bool
    error_message: str
    warning_message: str
    prediction_result: Optional[DualModelPredictionResult]
    features_dict: Dict[str, float]
    risk_indicators: List[RiskIndicator]
    disclaimer: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    parsed_components: Dict[str, Any] = field(default_factory=dict)


def evaluate_risk_indicators(features: Dict[str, float]) -> List[RiskIndicator]:
    """Generates plain-language cybersecurity risk indicators from extracted features."""
    indicators: List[RiskIndicator] = []

    # 1. IP Address Hostname
    if features.get("is_ip_address", 0) == 1:
        indicators.append(RiskIndicator(
            feature_name="is_ip_address",
            display_title="Raw IP Address Hostname",
            value="Active (IPv4/IPv6)",
            severity="High",
            explanation="The URL uses a raw numerical IP address instead of a registered domain name. Phishing infrastructure frequently utilizes IP hosts to bypass domain reputation checks."
        ))

    # 2. Known URL Shortener
    if features.get("is_shortener", 0) == 1:
        indicators.append(RiskIndicator(
            feature_name="is_shortener",
            display_title="URL Shortening Service",
            value="Detected",
            severity="High",
            explanation="The domain belongs to a URL shortening provider. Attackers often employ shorteners to conceal malicious destination paths from visual inspection."
        ))

    # 3. Sensitive Phishing Keywords
    if features.get("has_suspicious_keyword", 0) == 1:
        indicators.append(RiskIndicator(
            feature_name="has_suspicious_keyword",
            display_title="Sensitive Authentication Token",
            value="Detected",
            severity="Medium",
            explanation="The URL contains authentication or account-related keywords (e.g., 'login', 'verify', 'update'). Phishing pages commonly use these to lure targets into entering credentials."
        ))

    # 4. Unusual Port
    if features.get("has_unusual_port", 0) == 1:
        indicators.append(RiskIndicator(
            feature_name="has_unusual_port",
            display_title="Non-Standard Port",
            value="Custom Port Specified",
            severity="Medium",
            explanation="The URL explicitly targets a non-standard port outside standard HTTP (80) or HTTPS (443), often indicating rogue temporary server hosting."
        ))

    # 5. Excessive Hyphens
    hyphens = features.get("count_hyphens", 0)
    if hyphens >= 3:
        indicators.append(RiskIndicator(
            feature_name="count_hyphens",
            display_title="Multiple Hyphens",
            value=f"{int(hyphens)} occurrences",
            severity="Medium",
            explanation=f"Found {int(hyphens)} hyphens in the URL. Attackers frequently use hyphenated brand names (e.g., 'paypal-security-update.com') to mislead users."
        ))

    # 6. Userinfo '@' Symbol
    at_count = features.get("count_at", 0)
    if at_count > 0:
        indicators.append(RiskIndicator(
            feature_name="count_at",
            display_title="Userinfo '@' Symbol Present",
            value=f"{int(at_count)} occurrences",
            severity="High",
            explanation="The '@' symbol causes web browsers to ignore text to its left and treat text to its right as the real destination host."
        ))

    # 7. Subdomain Depth
    subdomains = features.get("count_subdomains", 0)
    if subdomains >= 2:
        indicators.append(RiskIndicator(
            feature_name="count_subdomains",
            display_title="Excessive Subdomain Levels",
            value=f"{int(subdomains)} subdomain levels",
            severity="Medium",
            explanation=f"Found {int(subdomains)} subdomains. Multiple subdomain levels are often used to mimic trusted domains (e.g., 'login.apple.com.attacker.biz')."
        ))

    # 8. Protocol Scheme (HTTPS Check with Disclaimer)
    is_https = features.get("is_https", 0)
    indicators.append(RiskIndicator(
        feature_name="is_https",
        display_title="Transport Layer Security (HTTPS)",
        value="HTTPS" if is_https == 1 else "HTTP (Unencrypted)",
        severity="Neutral" if is_https == 1 else "Medium",
        explanation=(
            "HTTPS encrypts communication between browser and server, but does NOT guarantee legitimacy. "
            "Modern phishing websites routinely obtain free, valid TLS certificates."
            if is_https == 1 else
            "Unencrypted HTTP transmission: Credentials entered on this page would travel in plain text."
        )
    ))

    # 9. URL Length
    url_len = features.get("url_length", 0)
    if url_len > 100:
        indicators.append(RiskIndicator(
            feature_name="url_length",
            display_title="Excessive URL Length",
            value=f"{int(url_len)} characters",
            severity="Low",
            explanation=f"The URL is notably long ({int(url_len)} characters). Phishing URLs frequently contain long token parameters or nested redirection strings."
        ))

    return indicators


def analyze_url(
    raw_url: str,
    models: Optional[Tuple[Any, Any, Dict]] = None
) -> URLAnalysisReport:
    """Executes full URL validation, feature extraction, and dual model inference."""
    is_valid, norm_url, err_msg, warn_msg = validate_and_normalize_url(raw_url)

    disclaimer = (
        "Disclaimer: This classification is generated by supervised machine-learning algorithms "
        "(Decision Tree and Random Forest) evaluating URL-based structural and lexical features only. "
        "It does not fetch website content, inspect certificates, or guarantee absolute safety. "
        "Always exercise caution when interacting with unknown links."
    )

    if not is_valid:
        return URLAnalysisReport(
            original_url=raw_url or "",
            normalized_url="",
            is_valid=False,
            error_message=err_msg,
            warning_message="",
            prediction_result=None,
            features_dict={},
            risk_indicators=[],
            disclaimer=disclaimer,
            timestamp=datetime.utcnow(),
            parsed_components={}
        )

    # Parse structural URL anatomy safely without visiting
    p = urlparse(norm_url)
    parsed_comp = {
        "scheme": p.scheme or "http",
        "hostname": p.hostname or "",
        "port": p.port if p.port else ("443" if p.scheme == "https" else "80"),
        "has_explicit_port": (p.port is not None),
        "path": p.path or "/",
        "query": p.query,
        "has_query": bool(p.query),
        "fragment": p.fragment,
        "has_fragment": bool(p.fragment)
    }

    # Extract 18 Canonical Features
    feat_vec, feat_dict = extract_url_features(norm_url)

    # Dual ML Model Inference
    pred_result = predict_url(feat_vec, models=models)

    # Plain-Language Risk Indicators
    indicators = evaluate_risk_indicators(feat_dict)

    return URLAnalysisReport(
        original_url=raw_url,
        normalized_url=norm_url,
        is_valid=True,
        error_message="",
        warning_message=warn_msg,
        prediction_result=pred_result,
        features_dict=feat_dict,
        risk_indicators=indicators,
        disclaimer=disclaimer,
        timestamp=datetime.utcnow(),
        parsed_components=parsed_comp
    )

