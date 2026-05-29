"""Noise filtering engine — removes static assets and non-API traffic."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Static file extensions to filter out
STATIC_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".map",
        ".webp",
        ".bmp",
    }
)

# Path prefixes that indicate static/content routes
STATIC_PATH_PREFIXES: frozenset[str] = frozenset(
    {
        "/_next",
        "/static",
        "/fonts",
        "/assets",
        "/images",
        "/img",
        "/css",
        "/js",
        "/favicon",
        "/i18n",
        "/locales",
        "/translations",
        "/lang",
    }
)

# Path substrings that indicate non-business content
NOISE_PATH_SUBSTRINGS: frozenset[str] = frozenset(
    {
        "/i18n/",
        "/assets/",
        "/locales/",
        "/translations/",
        "/lang/",
        "/_next/",
        "/static/",
        "/webpack",
        "/hot-update",
        "/chunk.",
        "/vendor.",
        "/runtime.",
        "/polyfill",
        "/swagger-ui",
        "/api-docs",
    }
)

# Content types that are considered API candidates
API_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/json",
        "application/graphql",
        "application/graphql+json",
        "application/graphql-response+json",
    }
)

# Content types to keep (API + form + partial HTML for XHR)
KEEP_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/json",
        "application/graphql",
        "application/graphql+json",
        "application/graphql-response+json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/xml",
        "text/xml",
    }
)

# GraphQL path indicators
GRAPHQL_PATHS: frozenset[str] = frozenset(
    {
        "/graphql",
        "/api/graphql",
        "/gql",
        "/query",
        "/graph",
    }
)


class FilterResult:
    """Result of a filtering decision."""

    __slots__ = ("passed", "reason")

    def __init__(self, passed: bool, reason: str = ""):
        self.passed = passed
        self.reason = reason

    def __bool__(self) -> bool:
        return self.passed


def should_filter_request(
    path: str,
    content_type: str | None = None,
    method: str = "",
    url: str = "",
) -> FilterResult:
    """Determine whether a request should be filtered out as noise.

    Returns FilterResult with:
    - passed=True  → keep the request
    - passed=False → filter it out (reason included)

    Filtering logic:
    1. Filter by static file extension
    2. Filter by static path prefix
    3. Keep if content_type is API-related
    4. Keep if path looks like GraphQL
    5. Keep if path starts with /api/
    6. Filter everything else (likely static HTML page loads)
    """
    parsed = urlparse(url) if url else None
    actual_path = parsed.path if parsed else path

    # 1. Noise path substring check (most specific patterns)
    path_lower = actual_path.lower()
    for substr in NOISE_PATH_SUBSTRINGS:
        if substr in path_lower:
            return FilterResult(
                passed=False, reason=f"noise_substring:{substr}"
            )

    # 2. Static path prefix check
    for prefix in STATIC_PATH_PREFIXES:
        if path_lower.startswith(prefix):
            return FilterResult(
                passed=False, reason=f"static_prefix:{prefix}"
            )

    # 3. Static extension check
    for ext in STATIC_EXTENSIONS:
        if actual_path.lower().endswith(ext):
            return FilterResult(
                passed=False, reason=f"static_extension:{ext}"
            )

    # 3. API content type → always keep
    if content_type:
        ct_normalized = content_type.lower().split(";")[0].strip()
        if ct_normalized in API_CONTENT_TYPES:
            return FilterResult(passed=True, reason="api_content_type")
        if ct_normalized in KEEP_CONTENT_TYPES:
            return FilterResult(passed=True, reason="keep_content_type")

    # 4. GraphQL path
    for gql_path in GRAPHQL_PATHS:
        if actual_path.lower() == gql_path or actual_path.lower().startswith(gql_path + "/"):
            return FilterResult(passed=True, reason="graphql_path")

    # 5. /api/ prefix
    if actual_path.lower().startswith("/api/"):
        return FilterResult(passed=True, reason="api_path_prefix")

    # 6. Keep form-urlencoded and multipart even without /api/ prefix
    if content_type:
        ct_lower = content_type.lower().split(";")[0].strip()
        if ct_lower in ("application/x-www-form-urlencoded", "multipart/form-data"):
            return FilterResult(passed=True, reason="form_content_type")

    # 7. POST/PUT/PATCH/DELETE to non-static paths likely API
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return FilterResult(passed=True, reason="mutation_method")

    # 8. XHR/fetch indicator — Accept header containing application/json
    #    (This is checked upstream in the normalizer by inspecting headers)

    # Default: filter out
    return FilterResult(passed=False, reason="likely_static_page")


def is_api_candidate(
    content_type: str | None,
    path: str = "",
    method: str = "",
) -> bool:
    """Determine if a transaction is an API candidate for authorization testing.

    Flags application/json and other API content types as candidates.
    """
    if not content_type:
        # Check path/method heuristics
        if path.lower().startswith("/api/"):
            return True
        for gql_path in GRAPHQL_PATHS:
            if path.lower() == gql_path or path.lower().startswith(gql_path + "/"):
                return True
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            return True
        return False

    ct_normalized = content_type.lower().split(";")[0].strip()
    return ct_normalized in API_CONTENT_TYPES


def detect_content_type_category(content_type: str | None) -> str:
    """Normalize content type into a category string.

    Returns one of: json, graphql, form_urlencoded, multipart, xml, html, other
    """
    if not content_type:
        return "other"

    ct = content_type.lower().split(";")[0].strip()

    if ct == "application/json":
        return "json"
    if "graphql" in ct:
        return "graphql"
    if ct == "application/x-www-form-urlencoded":
        return "form_urlencoded"
    if ct == "multipart/form-data":
        return "multipart"
    if ct in ("application/xml", "text/xml"):
        return "xml"
    if "html" in ct:
        return "html"

    return "other"