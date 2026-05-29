"""JWT Intelligence Layer — Automatic detection and decoding of JWT tokens.

Extracts identity claims (role, permissions, tenant, scope) from JWT tokens
found in Authorization headers or cookies, WITHOUT verifying signatures.

This module builds the WHO dimension of authorization intelligence.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── JWT Pattern Detection ──

# JWT regex: three base64url-encoded segments separated by dots
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)

# Common header names where JWTs are found
AUTH_HEADER_KEYS = {"authorization", "x-access-token", "x-auth-token"}

# Common cookie names where JWTs are found
JWT_COOKIE_NAMES = {"token", "access_token", "auth_token", "id_token", "jwt"}


# ── Role Name Normalization ──

# Mapping of known role name patterns to normalized snake_case
ROLE_NORMALIZATION_MAP: dict[str, str] = {
    "platform admin": "platform_admin",
    "platformadmin": "platform_admin",
    "institute admin": "institute_admin",
    "instituteadmin": "institute_admin",
    "super admin": "super_admin",
    "superadmin": "super_admin",
    "system admin": "system_admin",
    "systemadmin": "system_admin",
    "org admin": "org_admin",
    "orgadmin": "org_admin",
    "organization admin": "org_admin",
    "organizationadmin": "org_admin",
    "school admin": "school_admin",
    "schooladmin": "school_admin",
}

# Keywords that indicate administrative privilege
ADMIN_KEYWORDS = {"admin", "administrator", "superuser", "root", "manager", "owner"}

# Privilege tier inference keywords and their base scores
PRIVILEGE_KEYWORDS: dict[str, int] = {
    "platform": 100,
    "super": 90,
    "system": 80,
    "admin": 70,
    "manager": 60,
    "owner": 60,
    "institute": 50,
    "organization": 50,
    "school": 50,
    "tenant": 40,
    "editor": 30,
    "member": 20,
    "user": 10,
    "viewer": 5,
    "guest": 1,
    "anonymous": 0,
}


# ── Claim Extraction Config ──

# JWT claim names that may contain role information
ROLE_CLAIM_NAMES = [
    "role", "roles", "role_id", "user_role", "user_type", "account_type",
    "level", "privilege", "access_level", "group", "groups",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
]

# JWT claim names that may contain permission information
PERMISSION_CLAIM_NAMES = [
    "permissions", "perms", "prms", "scope", "scopes", "capabilities",
    "authorities", "entitlements", "privileges", "actions",
]

# JWT claim names that may contain tenant information
TENANT_CLAIM_NAMES = [
    "tenant", "tenant_id", "tenantId", "org_id", "orgId",
    "organization", "organization_id", "organizationId",
    "institute", "institute_id", "instituteId",
    "school", "school_id", "schoolId",
    "company", "company_id", "companyId",
    "account", "account_id", "accountId",
    "customer", "customer_id", "customerId",
]

# JWT claim names for issuer/audience
ISSUER_CLAIM_NAMES = ["iss", "issuer"]
AUDIENCE_CLAIM_NAMES = ["aud", "audience"]
EXPIRY_CLAIM_NAMES = ["exp", "expiry", "expires_at"]


def _safe_b64url_decode(data: str) -> str:
    """Decode a base64url-encoded string without strict padding."""
    try:
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
    except Exception:
        return ""


def detect_jwt_in_headers(headers: dict[str, str]) -> str | None:
    """Detect a JWT token in HTTP headers.

    Checks Authorization: Bearer <token> and custom auth headers.
    """
    for key, value in headers.items():
        lower_key = key.lower()
        if lower_key in AUTH_HEADER_KEYS:
            # Strip "Bearer " prefix if present
            token = re.sub(r"^Bearer\s+", "", value, flags=re.IGNORECASE).strip()
            if JWT_PATTERN.search(token):
                # Extract the first matching JWT
                match = JWT_PATTERN.search(token)
                return match.group(0) if match else None
    return None


def detect_jwt_in_cookies(cookies: dict[str, str]) -> str | None:
    """Detect a JWT token in cookies."""
    for key, value in cookies.items():
        lower_key = key.lower()
        if lower_key in JWT_COOKIE_NAMES:
            if JWT_PATTERN.search(value):
                match = JWT_PATTERN.search(value)
                return match.group(0) if match else None
    return None


def detect_jwt(body: str | None) -> str | None:
    """Detect a JWT token in a request body (e.g. JSON with token field)."""
    if not body:
        return None
    match = JWT_PATTERN.search(body)
    return match.group(0) if match else None


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode JWT payload without signature verification.

    Returns the claims dictionary from the payload segment.
    """
    parts = token.split(".")
    if len(parts) != 3:
        logger.warning("Invalid JWT structure: expected 3 segments, got %d", len(parts))
        return {}

    payload_segment = parts[1]
    decoded = _safe_b64url_decode(payload_segment)
    if not decoded:
        logger.warning("Failed to decode JWT payload segment")
        return {}

    try:
        claims = json.loads(decoded)
        if not isinstance(claims, dict):
            logger.warning("JWT payload is not a JSON object")
            return {}
        return claims
    except json.JSONDecodeError:
        logger.warning("JWT payload is not valid JSON")
        return {}


def normalize_role_name(raw_role: str) -> str:
    """Normalize a role name to snake_case convention.

    Examples:
        Platform Admin → platform_admin
        Institute Admin → institute_admin
        super-admin → super_admin
        SuperUser → super_user
    """
    if not raw_role:
        return ""

    lower = raw_role.strip().lower()

    # Check direct mapping first
    if lower in ROLE_NORMALIZATION_MAP:
        return ROLE_NORMALIZATION_MAP[lower]

    # Replace common separators with underscores
    normalized = re.sub(r"[\s\-\.]+", "_", lower)

    # Remove consecutive underscores
    normalized = re.sub(r"_+", "_", normalized)

    # Strip leading/trailing underscores
    normalized = normalized.strip("_")

    return normalized if normalized else lower


def infer_privilege_tier(
    role: str = "",
    permissions: list[str] | None = None,
    endpoint_coverage: int = 0,
) -> int:
    """Infer a privilege tier score (0-100) from role, permissions, and coverage.

    Higher scores indicate higher privilege. The inference uses:
    - Role name keywords
    - Permission count
    - Admin keywords in role/permissions
    - Endpoint coverage (more endpoints accessed = potentially higher privilege)

    This is heuristic-based and does NOT hardcode role hierarchies.
    """
    score = 0

    # Score from role name keywords
    if role:
        role_lower = role.lower()
        for keyword, tier_score in PRIVILEGE_KEYWORDS.items():
            if keyword in role_lower:
                score = max(score, tier_score)
                break
        else:
            # Check for admin keywords
            for kw in ADMIN_KEYWORDS:
                if kw in role_lower:
                    score = max(score, 70)
                    break

    # Score from permissions count (more permissions = higher privilege)
    if permissions:
        perm_count = len(permissions)
        if perm_count >= 50:
            score = max(score, 80)
        elif perm_count >= 20:
            score = max(score, 60)
        elif perm_count >= 10:
            score = max(score, 40)
        elif perm_count >= 5:
            score = max(score, 20)

        # Check for admin-like permissions
        for perm in permissions:
            perm_lower = perm.lower()
            for kw in ADMIN_KEYWORDS:
                if kw in perm_lower:
                    score = max(score, 70)
                    break

    # Score from endpoint coverage
    if endpoint_coverage >= 50:
        score = max(score, 70)
    elif endpoint_coverage >= 20:
        score = max(score, 50)

    # Ensure minimum score if we have any identity
    if role or permissions:
        score = max(score, 5)

    return min(score, 100)


def extract_identity_context(
    headers: dict[str, str],
    cookies: dict[str, str],
    body: str | None = None,
    endpoint_coverage: int = 0,
) -> dict[str, Any] | None:
    """Extract full identity context from a request by detecting and decoding JWTs.

    Returns None if no JWT token is found. Otherwise returns:
    {
        "role": "platform_admin",
        "privilege_tier": 100,
        "permissions": [...],
        "tenant_scope": "global" | "institute:xxx" | ...,
        "claims": {...},  # raw claims for replay-readiness
        "source": "header" | "cookie" | "body",
    }
    """
    # Try to find JWT token
    token = detect_jwt_in_headers(headers)
    source = "header"
    if not token:
        token = detect_jwt_in_cookies(cookies)
        source = "cookie"
    if not token:
        token = detect_jwt(body)
        source = "body"
    if not token:
        return None

    # Decode payload
    claims = decode_jwt_payload(token)
    if not claims:
        return None

    # Extract role
    raw_role = _extract_claim(claims, ROLE_CLAIM_NAMES)
    role = normalize_role_name(str(raw_role)) if raw_role else ""

    # Extract permissions
    raw_perms = _extract_claim(claims, PERMISSION_CLAIM_NAMES)
    permissions = _normalize_permissions(raw_perms)

    # Extract tenant info
    raw_tenant = _extract_claim(claims, TENANT_CLAIM_NAMES)
    tenant_scope = _build_tenant_scope(raw_tenant, role)

    # Extract standard claims
    issuer = _extract_claim(claims, ISSUER_CLAIM_NAMES) or ""
    audience = _extract_claim(claims, AUDIENCE_CLAIM_NAMES) or ""
    expiry = _extract_claim(claims, EXPIRY_CLAIM_NAMES) or ""

    # Infer privilege tier
    privilege_tier = infer_privilege_tier(
        role=role,
        permissions=permissions,
        endpoint_coverage=endpoint_coverage,
    )

    return {
        "role": role,
        "privilege_tier": privilege_tier,
        "permissions": permissions,
        "tenant_scope": tenant_scope,
        "issuer": str(issuer),
        "audience": str(audience),
        "expiry": str(expiry),
        "source": source,
        "claims": claims,  # Raw claims for future replay engine
    }


def _extract_claim(claims: dict[str, Any], claim_names: list[str]) -> Any:
    """Extract the first matching claim from a JWT payload."""
    for name in claim_names:
        if name in claims:
            return claims[name]
    return None


def _normalize_permissions(raw_perms: Any) -> list[str]:
    """Normalize permissions to a flat list of strings."""
    if raw_perms is None:
        return []
    if isinstance(raw_perms, str):
        # Could be comma/space-separated
        return [p.strip() for p in re.split(r"[,\s]+", raw_perms) if p.strip()]
    if isinstance(raw_perms, list):
        result = []
        for p in raw_perms:
            if isinstance(p, str):
                result.append(p.strip())
            else:
                result.append(str(p))
        return result
    return [str(raw_perms)]


class JWTDecoder:
    """Stateless wrapper for JWT detection and decoding functions.

    Provides an object-oriented interface matching the NormalizationResult
    pipeline convention while delegating to module-level functions.
    """

    def decode_from_headers(self, headers: dict[str, str]) -> dict[str, Any] | None:
        """Detect and decode JWT from HTTP headers.

        Returns decoded claims dict or None.
        """
        token = detect_jwt_in_headers(headers)
        if not token:
            return None
        claims = decode_jwt_payload(token)
        return claims if claims else None

    def build_identity_context(
        self,
        jwt_result: dict[str, Any],
        endpoint_coverage: int = 0,
    ) -> dict[str, Any] | None:
        """Build full identity context from already-decoded JWT claims.

        Args:
            jwt_result: Decoded JWT claims dictionary.
            endpoint_coverage: Number of endpoints this identity has accessed.

        Returns:
            Identity context dict or None.
        """
        if not jwt_result:
            return None

        raw_role = _extract_claim(jwt_result, ROLE_CLAIM_NAMES)
        role = normalize_role_name(str(raw_role)) if raw_role else ""

        raw_perms = _extract_claim(jwt_result, PERMISSION_CLAIM_NAMES)
        permissions = _normalize_permissions(raw_perms)

        raw_tenant = _extract_claim(jwt_result, TENANT_CLAIM_NAMES)
        tenant_scope = _build_tenant_scope(raw_tenant, role)

        issuer = _extract_claim(jwt_result, ISSUER_CLAIM_NAMES) or ""
        audience = _extract_claim(jwt_result, AUDIENCE_CLAIM_NAMES) or ""
        expiry = _extract_claim(jwt_result, EXPIRY_CLAIM_NAMES) or ""

        privilege_tier = infer_privilege_tier(
            role=role,
            permissions=permissions,
            endpoint_coverage=endpoint_coverage,
        )

        return {
            "role": role,
            "privilege_tier": privilege_tier,
            "permissions": permissions,
            "tenant_scope": tenant_scope,
            "issuer": str(issuer),
            "audience": str(audience),
            "expiry": str(expiry),
            "source": "header",
            "claims": jwt_result,
        }


def _build_tenant_scope(
    tenant_id: str | None,
    role: str | None = None,
) -> str:
    """
    Infer tenant scope from role + tenant claims.

    Rules:
    - platform_admin/super_admin/root => global
    - tenant identifier present => single_tenant
    - no tenant information => global (legacy compatibility)
    """

    normalized_role = (role or "").lower()

    global_roles = {
        "platform_admin",
        "super_admin",
        "root",
    }

    if normalized_role in global_roles:
        return "global"

    if tenant_id:
        return "single_tenant"

    # Legacy compatibility:
    # absence of tenant claims implies unrestricted/global
    return "global"