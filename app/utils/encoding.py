"""Encoding utilities — safe Base64 decoding with error handling."""

from __future__ import annotations

import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def decode_base64(data: str) -> Optional[str]:
    """Safely decode a Base64-encoded string.

    Returns None on failure instead of raising.
    """
    if not data or not data.strip():
        return ""
    try:
        decoded_bytes = base64.b64decode(data, validate=False)
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("base64 decode error: %s", exc)
        return None


def safe_b64_decode(data: str) -> str:
    """Safely decode a Base64-encoded string, returning empty string on failure.

    Unlike decode_base64 which returns None on failure, this always returns a string.
    Handles standard Base64, URL-safe Base64, and whitespace in encoded data.
    """
    if not data or not data.strip():
        return ""
    try:
        # Strip whitespace/newlines that some encoders insert
        cleaned = "".join(data.split())

        # Validate: only valid base64 characters allowed (A-Z, a-z, 0-9, +, /, =)
        import re
        if not re.match(r"^[A-Za-z0-9+/]+=*$", cleaned):
            return ""

        # Try standard decode first (with padding fix)
        padded = cleaned + "=" * (-len(cleaned) % 4)
        decoded_bytes = base64.b64decode(padded, validate=True)
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        try:
            # Fallback: URL-safe base64
            cleaned = "".join(data.split())
            # Validate URL-safe chars (A-Z, a-z, 0-9, -, _, =)
            if not re.match(r"^[A-Za-z0-9\-_=]+$", cleaned):
                return ""
            padded = cleaned + "=" * (-len(cleaned) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("safe_b64_decode error: %s", exc)
            return ""


def is_base64(data: str) -> bool:
    """Heuristic check: does the string look like Base64?"""
    if not data or not data.strip():
        return False
    try:
        decoded = base64.b64decode(data, validate=True)
        # Try to decode as text — if it looks like binary, reject
        decoded.decode("utf-8")
        return True
    except Exception:
        return False