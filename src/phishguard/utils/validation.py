"""Input validation and safe URL normalization module for PhishGuard AI.

Ensures submitted URLs are structurally well-formed, within length limits, and safe
to parse without making any external network requests or executing content.
"""

from typing import Tuple
from urllib.parse import urlparse
import re


MAX_URL_LENGTH = 2048


class URLValidationError(Exception):
    """Raised when URL input fails basic security or structural validation."""
    pass


def validate_and_normalize_url(raw_input: str) -> Tuple[bool, str, str, str]:
    """Validates and normalizes user input without performing any network request.
    
    Args:
        raw_input: Raw string entered by the user.
        
    Returns:
        (is_valid, normalized_url, error_message, warning_message)
    """
    if raw_input is None:
        return False, "", "No URL provided.", ""

    url_str = raw_input.strip()

    if not url_str:
        return False, "", "Please enter a valid website URL to analyze.", ""

    # Length guard
    if len(url_str) > MAX_URL_LENGTH:
        return (
            False,
            "",
            f"Input exceeds maximum allowed length of {MAX_URL_LENGTH} characters.",
            ""
        )

    # Check for unprintable/dangerous control characters
    if any(ord(char) < 32 or ord(char) == 127 for char in url_str):
        return (
            False,
            "",
            "Input contains invalid or unprintable control characters.",
            ""
        )

    warning_msg = ""

    # Scheme normalization: if missing, prepend https:// for uniform parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_str):
        normalized_url = f"https://{url_str}"
        warning_msg = (
            "Notice: No protocol scheme was provided. Prepending 'https://' for lexical parsing only. "
            "This assumption does not verify that the live host supports HTTPS."
        )
    else:
        normalized_url = url_str

    # Validate structure using standard urllib.parse
    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname

        if not hostname:
            return (
                False,
                "",
                "Could not extract a valid domain or hostname from the provided URL.",
                ""
            )

        # Basic hostname format verification: must have at least one character
        if len(hostname.strip()) == 0:
            return False, "", "Extracted hostname is empty.", ""

        # Reject local broadcast or invalid formatting
        if " " in hostname:
            return False, "", "Hostname contains invalid spaces.", ""

        return True, normalized_url, "", warning_msg

    except Exception as e:
        return False, "", f"Malformed URL could not be parsed: {str(e)}", ""
