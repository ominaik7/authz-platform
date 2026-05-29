"""Endpoint Intelligence Layer — Classify endpoint sensitivity automatically.

Determines risk level, admin-only status, tenant-awareness, and endpoint type
from URL patterns, HTTP methods, and JWT correlation data.

This module builds the WHICH endpoint characteristics dimension.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Endpoint Type Patterns ──

# Maps URL path keywords to semantic endpoint types
ENDPOINT_TYPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"dashboard|dshbrd|dshbrddtl", re.I), "dashboard_reporting"),
    (re.compile(r"report|rptsvc|rpt|analytics|statistic|metric", re.I), "reporting"),
    (re.compile(r"admin|adm|manage|mgmt", re.I), "administration"),
    (re.compile(r"user|usr|account|member|profile", re.I), "user_management"),
    (re.compile(r"role|permission|privilege|auth|access", re.I), "access_control"),
    (re.compile(r"institute|school|org|organization|tenant", re.I), "tenant_management"),
    (re.compile(r"config|setting|preference|option", re.I), "configuration"),
    (re.compile(r"billing|payment|invoice|subscription|pricing", re.I), "billing"),
    (re.compile(r"course|class|curriculum|lesson", re.I), "learning"),
    (re.compile(r"exam|quiz|assessment|test", re.I), "assessment"),
    (re.compile(r"certificate|cert|credential|diploma", re.I), "certification"),
    (re.compile(r"notification|notify|alert|email", re.I), "notifications"),
    (re.compile(r"search|query|filter|lookup", re.I), "search"),
    (re.compile(r"upload|import|export|download|file|media", re.I), "data_transfer"),
    (re.compile(r"audit|log|event|history|activity", re.I), "audit"),
    (re.compile(r"api/v[0-9]+/auth", re.I), "authentication"),
    (re.compile(r"login|signin|signup|register|register|forgot|reset", re.I), "authentication"),
    (re.compile(r"health|status|ping|version|info", re.I), "system_info"),
    (re.compile(r"swagger|openapi|docs|api-docs", re.I), "documentation"),
]

# ── Risk Classification ──

# High-risk keywords in URL paths
HIGH_RISK_KEYWORDS = [
    "admin", "settings", "user", "role", "billing", "report",
    "tenant", "config", "institute", "permission", "privilege",
    "delete", "remove", "password", "secret", "key", "token",
    "audit", "security", "access", "manage", "management",
    "dshbrd", "dashboard",
]

# Medium-risk keywords
MEDIUM_RISK_KEYWORDS = [
    "update", "edit", "modify", "create", "add", "import",
    "export", "upload", "profile", "notification", "course",
    "class", "exam", "assessment",
]

# Low-risk keywords (generally safe, read-only)
LOW_RISK_KEYWORDS = [
    "list", "get", "search", "query", "filter", "lookup",
    "health", "status", "ping", "version", "info", "docs",
    "swagger", "openapi",
]

# HTTP methods that indicate state-changing operations
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Risk score modifiers for HTTP methods
METHOD_RISK_MODIFIERS: dict[str, int] = {
    "DELETE": 30,
    "POST": 20,
    "PUT": 15,
    "PATCH": 15,
    "GET": 0,
    "HEAD": -5,
    "OPTIONS": -10,
}


def classify_endpoint(
    method: str,
    path: str,
    roles_observed: list[str] | None = None,
    privilege_tiers: list[int] | None = None,
) -> dict[str, Any]:
    """Classify an endpoint's sensitivity and characteristics.

    Args:
        method: HTTP method (GET, POST, etc.)
        path: URL path component
        roles_observed: List of roles that have been seen accessing this endpoint
        privilege_tiers: Privilege tier scores of those roles

    Returns:
        {
            "endpoint_type": "dashboard_reporting",
            "sensitivity": "high",
            "risk_score": 75,
            "tenant_aware": True,
            "admin_only": True,
            "state_changing": True,
            "auth_required": True,
            "high_risk_factors": ["admin_keyword", "state_changing_method"],
            "classification_confidence": 0.85
        }
    """
    path_lower = path.lower()
    method_upper = method.upper()

    # Determine endpoint type
    endpoint_type = _determine_endpoint_type(path_lower)

    # Calculate risk score
    risk_score = _calculate_risk_score(path_lower, method_upper, roles_observed, privilege_tiers)

    # Determine sensitivity level from risk score
    if risk_score >= 25:
        sensitivity = "high"
    elif risk_score >= 10:
        sensitivity = "medium"
    else:
        sensitivity = "low"

    # Determine if endpoint is tenant-aware
    tenant_aware = _is_tenant_aware(path_lower)

    # Determine if admin-only
    admin_only = _is_admin_only(path_lower, method_upper, roles_observed, privilege_tiers)

    # Determine if state-changing
    state_changing = method_upper in STATE_CHANGING_METHODS

    # Determine if auth is likely required
    auth_required = _is_auth_required(path_lower, method_upper)

    # Collect high risk factors
    high_risk_factors = _collect_risk_factors(path_lower, method_upper, roles_observed, privilege_tiers)

    # Calculate classification confidence
    confidence = _calculate_confidence(path_lower, roles_observed)

    # Determine if endpoint serves static content
    is_static = _is_static_content(path_lower)

    return {
        "endpoint_type": endpoint_type,
        "sensitivity": sensitivity,
        "risk_score": risk_score,
        "tenant_aware": tenant_aware,
        "admin_only": admin_only,
        "state_changing": state_changing,
        "auth_required": auth_required,
        "is_static": is_static,
        "high_risk_factors": high_risk_factors,
        "classification_confidence": confidence,
    }


def _determine_endpoint_type(path: str) -> str:
    """Determine the semantic type of an endpoint from its path."""
    for pattern, endpoint_type in ENDPOINT_TYPE_PATTERNS:
        if pattern.search(path):
            return endpoint_type
    return "general"


def _calculate_risk_score(
    path: str,
    method: str,
    roles_observed: list[str] | None = None,
    privilege_tiers: list[int] | None = None,
) -> int:
    """Calculate a risk score (0-100) for an endpoint.

    Considers: path keywords, HTTP method, and JWT correlation data.
    """
    score = 0

    # High-risk keywords
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in path:
            score += 15
            break  # Only count once

    # Medium-risk keywords
    if score < 15:
        for keyword in MEDIUM_RISK_KEYWORDS:
            if keyword in path:
                score += 8
                break

    # State-changing method modifier
    score += METHOD_RISK_MODIFIERS.get(method, 0)

    # JWT correlation: if only high-tier roles access this endpoint, increase risk
    if privilege_tiers:
        min_tier = min(privilege_tiers) if privilege_tiers else 0
        if min_tier >= 70:
            score += 20  # Only high-privilege roles → likely admin endpoint
        elif min_tier >= 40:
            score += 10

    # If all observed roles contain 'admin', increase risk
    if roles_observed:
        admin_roles = [r for r in roles_observed if "admin" in r.lower()]
        if admin_roles and len(admin_roles) == len(roles_observed):
            score += 15  # All roles are admin → definitely admin endpoint

    # Cap at 100
    return min(max(score, 0), 100)


def _is_tenant_aware(path: str) -> bool:
    """Determine if an endpoint appears to be tenant-scoped.

    Checks for tenant-related path segments and ID-like patterns.
    """
    tenant_keywords = [
        "institute", "organization", "org", "tenant", "company",
        "school", "customer", "account", "branch", "division",
    ]
    for keyword in tenant_keywords:
        if keyword in path:
            return True

    # Check for ID-like segments in path (e.g., /api/resource/64e85a...)
    segments = path.split("/")
    for segment in segments:
        if re.match(r"^[0-9a-fA-F]{16,}$", segment):  # Mongo/ObjectId
            return True
        if re.match(r"^\d{4,}$", segment):  # Long numeric IDs
            return True

    return False


def _is_admin_only(
    path: str,
    method: str,
    roles_observed: list[str] | None = None,
    privilege_tiers: list[int] | None = None,
) -> bool:
    """Determine if an endpoint is likely admin-only.

    Uses path keywords, HTTP method, and JWT correlation.
    """
    # Strong admin indicators in path
    strong_admin_indicators = [
        "admin", "management", "manage", "config", "configuration",
        "settings", "role", "permission", "privilege",
    ]
    for indicator in strong_admin_indicators:
        if indicator in path:
            return True

    # State-changing methods on user/tenant management paths
    if method in STATE_CHANGING_METHODS:
        management_paths = ["user", "institute", "organization", "billing"]
        for mp in management_paths:
            if mp in path:
                return True

    # JWT correlation: only high-tier roles observed
    if privilege_tiers and all(t >= 70 for t in privilege_tiers):
        return True

    # JWT correlation: only admin roles observed
    if roles_observed and all("admin" in r.lower() for r in roles_observed):
        return True

    return False


def _is_auth_required(path: str, method: str) -> bool:
    """Determine if an endpoint likely requires authentication.

    Most non-GET endpoints require auth. GET endpoints on sensitive paths also do.
    """
    # State-changing methods almost always require auth
    if method in STATE_CHANGING_METHODS:
        return True

    # Public paths that typically don't require auth
    public_paths = [
        "/login", "/signin", "/signup", "/register", "/forgot",
        "/reset", "/public", "/health", "/status", "/ping",
        "/docs", "/swagger", "/openapi",
    ]
    path_lower = path.lower()
    for public in public_paths:
        if public in path_lower:
            return False

    # Everything else likely requires auth
    return True


def _collect_risk_factors(
    path: str,
    method: str,
    roles_observed: list[str] | None = None,
    privilege_tiers: list[int] | None = None,
) -> list[str]:
    """Collect a list of risk factor descriptions for an endpoint."""
    factors = []

    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in path:
            factors.append(f"high_risk_keyword:{keyword}")
            break

    if method in STATE_CHANGING_METHODS:
        factors.append(f"state_changing_method:{method}")

    if privilege_tiers and all(t >= 70 for t in privilege_tiers):
        factors.append("high_privilege_roles_only")

    if roles_observed and all("admin" in r.lower() for r in roles_observed):
        factors.append("admin_roles_only")

    if _is_tenant_aware(path):
        factors.append("tenant_aware_endpoint")

    return factors


def _calculate_confidence(path: str, roles_observed: list[str] | None = None) -> float:
    """Calculate confidence score for the classification.

    Higher confidence when we have JWT data and clear path signals.
    """
    confidence = 0.3  # Base confidence from path analysis alone

    # More path segments = more signal
    segments = [s for s in path.split("/") if s]
    if len(segments) >= 3:
        confidence += 0.1

    # JWT correlation data available
    if roles_observed:
        confidence += 0.2

    # Path has clear type signals
    for pattern, _ in ENDPOINT_TYPE_PATTERNS:
        if pattern.search(path):
            confidence += 0.1
            break

    return min(confidence, 1.0)


def _is_static_content(path: str) -> bool:
    """Determine if an endpoint serves static content (not a business API)."""
    static_patterns = [
        r"\.css$", r"\.js$", r"\.map$", r"\.png$", r"\.jpg$", r"\.jpeg$",
        r"\.gif$", r"\.svg$", r"\.ico$", r"\.woff", r"\.ttf$", r"\.eot$",
        r"/_next/", r"/static/", r"/assets/", r"/public/", r"/dist/",
        r"/build/", r"/vendor/", r"/third.party/",
    ]
    import re as _re
    for pattern in static_patterns:
        if _re.search(pattern, path):
            return True
    return False


class EndpointClassifier:
    """Stateless wrapper for endpoint classification functions.

    Provides an object-oriented interface matching the NormalizationResult
    pipeline convention while delegating to module-level functions.
    """

    def classify(
        self,
        method: str,
        path: str,
        identity_context: dict[str, Any] | None = None,
        request_body: str | None = None,
    ) -> dict[str, Any]:
        """Classify an endpoint's sensitivity and characteristics.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path
            identity_context: Identity context from JWT decoding (optional)
            request_body: Raw request body string (optional)

        Returns:
            Endpoint classification dictionary.
        """
        roles_observed = None
        privilege_tiers = None
        if identity_context:
            if identity_context.get("role"):
                roles_observed = [identity_context["role"]]
            if identity_context.get("privilege_tier") is not None:
                privilege_tiers = [identity_context["privilege_tier"]]

        return classify_endpoint(
            method=method,
            path=path,
            roles_observed=roles_observed,
            privilege_tiers=privilege_tiers,
        )
