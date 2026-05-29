"""Raw HTTP parser — converts raw HTTP text into structured request/response parts."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


@dataclass
class ParsedRequest:
    """Structured result of parsing a raw HTTP request."""

    method: str = ""
    path: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    body: str = ""
    host: str = ""
    full_url: str = ""


@dataclass
class ParsedResponse:
    """Structured result of parsing a raw HTTP response."""

    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: Optional[str] = None


def parse_raw_request(raw: str, url_hint: str = "") -> ParsedRequest:
    """Parse a raw HTTP request string into structured components.

    Supports GET, POST, PUT, PATCH, DELETE.

    Args:
        raw: The raw HTTP request text.
        url_hint: Optional URL from Burp metadata to reconstruct full URL.

    Returns:
        ParsedRequest with method, path, headers, cookies, query_params, body.
    """
    if not raw or not raw.strip():
        return ParsedRequest()

    try:
        lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")
    except Exception:
        return ParsedRequest()

    if not lines:
        return ParsedRequest()

    # --- Request line ---
    request_line = lines[0].strip()
    method, path, _ = _parse_request_line(request_line)

    # --- Headers ---
    headers: dict[str, str] = {}
    body_start_idx = 1
    for i in range(1, len(lines)):
        line = lines[i]
        if line.strip() == "":
            body_start_idx = i + 1
            break
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key:
                headers[key] = value
    else:
        body_start_idx = len(lines)

    # --- Body ---
    body_lines = lines[body_start_idx:]
    body = "\r\n".join(body_lines) if body_lines else ""

    # --- Host ---
    host = headers.get("Host", "")

    # --- Cookies ---
    cookies = _parse_cookies(headers.get("Cookie", ""))

    # --- Query Params ---
    query_params: dict[str, str] = {}
    parsed_path = urlparse(path)
    actual_path = parsed_path.path or path
    if parsed_path.query:
        qs = parse_qs(parsed_path.query, keep_blank_values=True)
        query_params = {k: v[0] if len(v) == 1 else ",".join(v) for k, v in qs.items()}

    # --- Full URL reconstruction ---
    full_url = _reconstruct_url(url_hint, host, path)

    return ParsedRequest(
        method=method,
        path=actual_path,
        headers=headers,
        cookies=cookies,
        query_params=query_params,
        body=body,
        host=host,
        full_url=full_url,
    )


def parse_raw_response(raw: str) -> ParsedResponse:
    """Parse a raw HTTP response string into structured components.

    Args:
        raw: The raw HTTP response text.

    Returns:
        ParsedResponse with status_code, headers, body, content_type.
    """
    if not raw or not raw.strip():
        return ParsedResponse()

    try:
        lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")
    except Exception:
        return ParsedResponse()

    if not lines:
        return ParsedResponse()

    # --- Status line ---
    status_code = _parse_status_line(lines[0])

    # --- Headers ---
    headers: dict[str, str] = {}
    body_start_idx = 1
    for i in range(1, len(lines)):
        line = lines[i]
        if line.strip() == "":
            body_start_idx = i + 1
            break
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key:
                headers[key] = value
    else:
        body_start_idx = len(lines)

    # --- Body ---
    body_lines = lines[body_start_idx:]
    body = "\r\n".join(body_lines) if body_lines else ""

    # --- Content-Type ---
    ct_header = headers.get("Content-Type", headers.get("content-type", ""))
    content_type = ct_header.split(";")[0].strip() if ct_header else None

    return ParsedResponse(
        status_code=status_code,
        headers=headers,
        body=body,
        content_type=content_type,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_request_line(line: str) -> tuple[str, str, str]:
    """Parse 'GET /path HTTP/1.1' into (method, path, version)."""
    parts = line.split()
    if len(parts) < 2:
        return ("", "", "")
    method = parts[0].upper()
    path = parts[1]
    version = parts[2] if len(parts) >= 3 else ""
    return (method, path, version)


def _parse_status_line(line: str) -> int:
    """Parse 'HTTP/1.1 200 OK' into status code."""
    parts = line.split()
    for part in parts[1:]:
        try:
            return int(part)
        except ValueError:
            continue
    return 0


def _parse_cookies(cookie_header: str) -> dict[str, str]:
    """Parse a Cookie header string into a dict."""
    if not cookie_header:
        return {}
    cookies: dict[str, str] = {}
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            key, _, value = pair.partition("=")
            cookies[key.strip()] = value.strip()
    return cookies


def _reconstruct_url(url_hint: str, host: str, path: str) -> str:
    """Reconstruct a full URL from hints.

    Priority:
    1. url_hint (from Burp metadata)
    2. host + path
    3. path only
    """
    if url_hint and url_hint.startswith(("http://", "https://")):
        # If path has query string, use url_hint as base and append path
        return url_hint

    scheme = "https"  # default assumption
    if host:
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path
        return f"{scheme}://{host}{path}"

    return path