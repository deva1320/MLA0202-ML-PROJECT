"""Central configuration module for PhishGuard AI.

Defines target labels, canonical 18-dimensional feature schema, model hyperparameters,
and cybersecurity theme styling constants.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

# Base Project Directories
PROJECT_NAME = "PhishGuard AI"
FULL_PROJECT_TITLE = "Phishing Website Detection Using URL-Based Feature Extraction with Decision Tree and Random Forest Algorithms"
TAGLINE = "Detect Phishing. Browse Safely."
APPLICATION_TYPE = "Browser-based Web Application"

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
ASSETS_DIR = PROJECT_ROOT / "assets"
STYLES_DIR = ASSETS_DIR / "styles"

# Target Classification Labels
CLASS_NAMES: List[str] = ["Legitimate", "Phishing"]
LABEL_TO_NAME: Dict[int, str] = {0: "Legitimate", 1: "Phishing"}
NAME_TO_LABEL: Dict[str, int] = {"Legitimate": 0, "Phishing": 1}

# UI & Alert Theme Colors
THEME_COLORS = {
    "background": "#0B1120",        # Deep Cybersecurity Navy
    "card_bg": "#131C31",           # Elevated Navy Card
    "card_hover": "#1A2642",        # Interactive Card Hover
    "accent_primary": "#0EA5E9",     # Cyber Cyan / Electric Blue
    "accent_secondary": "#14B8A6",   # Restrained Teal
    "status_safe": "#10B981",        # Emerald Green (Legitimate)
    "status_phish": "#EF4444",       # Alert Crimson (Phishing)
    "text_primary": "#F8FAFC",       # Crisp Slate White
    "text_muted": "#94A3B8",         # Slate Muted Gray
    "border": "rgba(255, 255, 255, 0.08)"
}

# Common URL Shortener Domains (Strictly lexical matching, zero external requests)
KNOWN_URL_SHORTENERS: Tuple[str, ...] = (
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorte.st", "tiny.cc",
    "rebrand.ly", "sniply.io", "v.gd"
)

# Common Phishing Credential/Deception Keywords
SUSPICIOUS_KEYWORDS: Tuple[str, ...] = (
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "authenticate", "confirm", "password",
    "credential", "wallet", "recovery", "webscr", "ebayisapi"
)


@dataclass(frozen=True)
class FeatureConfig:
    """Canonical 18-dimensional feature specification."""

    feature_names: List[str] = field(default_factory=lambda: [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "count_dots",
        "count_hyphens",
        "count_at",
        "count_question",
        "count_equal",
        "count_ampersand",
        "count_percent",
        "count_digits",
        "count_subdomains",
        "is_ip_address",
        "is_https",
        "is_shortener",
        "has_suspicious_keyword",
        "has_unusual_port"
    ])

    feature_descriptions: Dict[str, str] = field(default_factory=lambda: {
        "url_length": "Total character count of the URL. Excessively long URLs are often used to conceal target hostnames.",
        "hostname_length": "Character length of the domain/host component.",
        "path_length": "Character count of the URL path segments.",
        "query_length": "Character count of HTTP GET parameters following '?' delimiter.",
        "count_dots": "Total number of dot (.) characters. Multiple dots often indicate excessive subdomain chaining.",
        "count_hyphens": "Total count of hyphens (-). Attackers frequently insert hyphens to mimic legitimate brand names (e.g. 'paypal-security.com').",
        "count_at": "Occurrences of '@' symbol. In standard URLs, '@' precedes host info and can obscure the true destination.",
        "count_question": "Occurrences of '?' denoting query strings.",
        "count_equal": "Count of '=' parameter assignments in queries.",
        "count_ampersand": "Count of '&' query parameter separators.",
        "count_percent": "Count of '%' percent-encoding markers, frequently used to disguise ASCII characters.",
        "count_digits": "Total numerical digits in the URL. Phishing URLs frequently use IP octets or random numerical hashes.",
        "count_subdomains": "Number of subdomain levels. More than 2 subdomains is common in phishing infrastructure.",
        "is_ip_address": "Indicates if the host is a raw IPv4/IPv6 numerical address rather than a registered domain.",
        "is_https": "Indicates HTTPS protocol scheme. (Note: Modern phishing sites may also use free TLS certificates).",
        "is_shortener": "Indicates whether the host belongs to a known URL shortening service used to mask destinations.",
        "has_suspicious_keyword": "Indicates presence of sensitive credential-harvesting tokens (e.g., 'login', 'verify', 'banking').",
        "has_unusual_port": "Indicates non-standard port numbers outside standard web ports (80, 443)."
    })

    @property
    def total_features_count(self) -> int:
        return len(self.feature_names)


@dataclass(frozen=True)
class MLConfig:
    """Hyperparameters and artifact paths for the two primary supervised classifiers."""
    random_state: int = 42
    test_size: float = 0.20
    cv_folds: int = 5

    # Decision Tree Classifier
    dt_max_depth: int = 8
    dt_min_samples_split: int = 5
    dt_min_samples_leaf: int = 2
    dt_criterion: str = "gini"

    # Random Forest Classifier
    rf_n_estimators: int = 150
    rf_max_depth: int = 12
    rf_min_samples_split: int = 4
    rf_min_samples_leaf: int = 2
    rf_criterion: str = "gini"

    # Artifact filenames
    dt_artifact_name: str = "decision_tree.joblib"
    rf_artifact_name: str = "random_forest.joblib"
    metadata_artifact_name: str = "model_metadata.json"


FEATURE_CONFIG = FeatureConfig()
ML_CONFIG = MLConfig()

