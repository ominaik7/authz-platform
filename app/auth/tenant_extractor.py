"""Tenant Scope Detection — Automatically identify tenant boundary parameters.

Detects tenant identifiers from URL paths, query parameters, request bodies,
and JWT claims. This module builds the WHICH tenant scope dimension.

Tenant boundaries are critical for horizontal privilege escalation testing:
a user in tenant A should NOT be able to access tenant B's data.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Tenant Parameter Detection ──

# Known tenant parameter name patterns (case-insensitive matching)
TENANT_PARAM_NAMES: dict[str, str] = {
    "tenantid": "tenant",
    "tenant_id": "tenant",
    "instituteid": "institute",
    "institute_id": "institute",
    "organizationid": "organization",
    "organization_id": "organization",
    "orgid": "organization",
    "org_id": "organization",
    "companyid": "company",
    "company_id": "company",
    "schoolid": "school",
    "school_id": "school",
    "customerid": "customer",
    "customer_id": "customer",
    "accountid": "account",
    "account_id": "account",
    "groupid": "group",
    "group_id": "group",
    "workspaceid": "workspace",
    "workspace_id": "workspace",
    "projectid": "project",
    "project_id": "project",
    "facilityid": "facility",
    "facility_id": "facility",
    "branchid": "branch",
    "branch_id": "branch",
    "divisionid": "division",
    "division_id": "division",
    "departmentid": "department",
    "department_id": "department",
}

# Regex pattern for matching tenant-like parameter names
TENANT_PARAM_PATTERN = re.compile(
    r"(tenant|institute|organization|org|company|school|customer|account|"
    r"group|workspace|project|facility|branch|division|department)"
    r"[_\-]?id$",
    re.IGNORECASE,
)

# ID value patterns
MONGO_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{24}$")
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    re.IGNORECASE,
)
NUMERIC_ID_PATTERN = re.compile(r"^\d{1,20}$")


def extract_tenant_parameters(
    path: str,
    query_params: dict[str, str],
    body: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Extract tenant boundary parameters from all parts of a request.

    Scans URL path segments, query parameters, request body (JSON),
    and custom headers for tenant identifiers.

    Returns:
        {
            "tenant_parameters": [{"name": "instituteId", "value": "64e85a...", "location": "query", "tenant_type": "institute"}],
            "primary_tenant": {"name": "instituteId", "value": "64e85a...", "tenant_type": "institute"},
            "tenant_count": 1,
            "multi_tenant": False
        }
    """
    tenant_params: list[dict[str, Any]] = []

    # 1. Scan path segments
    tenant_params.extend(_scan_path_segments(path))

    # 2. Scan query parameters
    tenant_params.extend(_scan_dict_params(query_params, "query"))

    # 3. Scan request body (JSON)
    if body:
        body_params = _scan_body(body)
        tenant_params.extend(body_params)

    # 4. Scan headers
    if headers:
        tenant_params.extend(_scan_headers(headers))

    # Deduplicate by (name, value)
    seen: set[tuple[str, str]] = set()
    unique_params: list[dict[str, Any]] = []
    for param in tenant_params:
        key = (param["name"].lower(), str(param["value"]))
        if key not in seen:
            seen.add(key)
            unique_params.append(param)

    # Determine primary tenant (first found, preferring path > query > body > header)
    primary_tenant: dict[str, Any] | None = None
    if unique_params:
        # Prefer path parameters, then query, then body, then headers
        location_priority = {"path": 0, "query": 1, "body": 2, "header": 3}
        unique_params.sort(key=lambda p: location_priority.get(p.get("location", "query"), 99))
        primary_tenant = unique_params[0]

    # Determine is_tenant_aware based on parameter names (not values)
    # and path keywords, regardless of whether values look like IDs
    is_tenant_aware = _is_request_tenant_aware(query_params, body, path, headers)

    return {
        "tenant_parameters": unique_params,
        "primary_tenant": primary_tenant,
        "tenant_count": len(unique_params),
        "multi_tenant": len(unique_params) > 1,
        "is_tenant_aware": is_tenant_aware,
    }


def _scan_path_segments(path: str) -> list[dict[str, Any]]:
    """Scan URL path segments for tenant-like parameter names.

    Detects patterns like /api/institutes/64e85a.../...
    """
    results: list[dict[str, Any]] = []
    segments = [s for s in path.split("/") if s]

    for i, segment in enumerate(segments):
        # Check if this segment looks like a tenant ID value
        if _looks_like_id_value(segment):
            # Look at the previous segment as the parameter name
            if i > 0:
                param_name = segments[i - 1]
                tenant_type = _classify_tenant_param(param_name)
                if tenant_type:
                    results.append({
                        "name": param_name,
                        "value": segment,
                        "location": "path",
                        "tenant_type": tenant_type,
                    })

    return results


def _scan_dict_params(params: dict[str, str], location: str) -> list[dict[str, Any]]:
    """Scan a dictionary of parameters for tenant-like names."""
    results: list[dict[str, Any]] = []
    for key, value in params.items():
        tenant_type = _classify_tenant_param(key)
        if tenant_type and value:
            results.append({
                "name": key,
                "value": value,
                "location": location,
                "tenant_type": tenant_type,
            })
    return results


def _scan_body(body: str) -> list[dict[str, Any]]:
    """Scan request body (JSON) for tenant-like parameter names."""
    results: list[dict[str, Any]] = []
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            results.extend(_scan_json_object(data, "body"))
    except (json.JSONDecodeError, TypeError):
        pass
    return results


def _scan_json_object(data: dict[str, Any], location: str, depth: int = 0) -> list[dict[str, Any]]:
    """Recursively scan a JSON object for tenant parameters."""
    results: list[dict[str, Any]] = []
    if depth > 3:  # Prevent deep recursion
        return results

    for key, value in data.items():
        tenant_type = _classify_tenant_param(key)
        if tenant_type:
            str_value = str(value) if value is not None else ""
            if str_value:
                results.append({
                    "name": key,
                    "value": str_value,
                    "location": location,
                    "tenant_type": tenant_type,
                })
        # Recurse into nested objects
        if isinstance(value, dict) and depth < 3:
            results.extend(_scan_json_object(value, location, depth + 1))

    return results


def _scan_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Scan request headers for tenant-like names."""
    results: list[dict[str, Any]] = []
    tenant_headers = {
        "x-tenant-id", "x-institute-id", "x-org-id", "x-organization-id",
        "x-company-id", "x-school-id", "x-customer-id", "x-account-id",
    }
    for key, value in headers.items():
        lower_key = key.lower()
        if lower_key in tenant_headers:
            tenant_type = _classify_tenant_param(key)
            if tenant_type:
                results.append({
                    "name": key,
                    "value": value,
                    "location": "header",
                    "tenant_type": tenant_type,
                })
    return results


def _classify_tenant_param(param_name: str) -> str | None:
    """Classify a parameter name as a tenant type.

    Returns the tenant type (e.g., 'institute', 'organization') or None.
    """
    lower = param_name.lower().replace("-", "_")

    # Direct lookup
    if lower in TENANT_PARAM_NAMES:
        return TENANT_PARAM_NAMES[lower]

    # Pattern match
    match = TENANT_PARAM_PATTERN.match(lower)
    if match:
        return match.group(1).lower()

    return None


def _looks_like_id_value(value: str) -> bool:
    """Check if a value looks like an ID (Mongo ID, UUID, or numeric)."""
    if not value:
        return False
    # String IDs that are long enough to look like real IDs
    if len(value) >= 6:
        return True
    # Short numeric IDs
    if NUMERIC_ID_PATTERN.match(value):
        return True
    return False


def _is_request_tenant_aware(
    query_params: dict[str, str],
    body: str | None,
    path: str,
    headers: dict[str, str] | None,
) -> bool:
    """Determine if a request is tenant-aware by checking for tenant-like
    parameter names (regardless of value format) and path keywords.

    Unlike _scan_dict_params which requires values to look like IDs,
    this function checks for the PRESENCE of tenant-like parameter names,
    which is a stronger signal for tenant-awareness.
    """
    # 1. Check query params for tenant-like names
    for key in query_params:
        if _classify_tenant_param(key) is not None:
            return True

    # 2. Check body JSON for tenant-like keys
    if body:
        try:
            data = json.loads(body)
            if isinstance(data, dict) and _json_has_tenant_keys(data):
                return True
        except (json.JSONDecodeError, TypeError):
            pass

    # 3. Check path for tenant keywords
    path_lower = path.lower()
    tenant_path_keywords = [
        "tenant", "institute", "organization", "org", "company",
        "school", "customer", "account", "branch", "division",
        "department", "workspace", "project", "facility",
    ]
    for keyword in tenant_path_keywords:
        if keyword in path_lower:
            return True

    # 4. Check headers for tenant-related headers
    if headers:
        tenant_headers = {
            "x-tenant-id", "x-institute-id", "x-org-id",
            "x-organization-id", "x-company-id",
        }
        for key in headers:
            if key.lower() in tenant_headers:
                return True

    return False


def _json_has_tenant_keys(data: dict[str, Any]) -> bool:
    """Check if a JSON object has any tenant-like keys (recursively)."""
    for key in data:
        if _classify_tenant_param(key) is not None:
            return True
        if isinstance(data[key], dict) and _json_has_tenant_keys(data[key]):
            return True
    return False


class TenantExtractor:
    """Stateless wrapper for tenant parameter extraction functions.

    Provides an object-oriented interface matching the NormalizationResult
    pipeline convention while delegating to module-level functions.
    """

    def extract_from_request(
        self,
        query_params: dict[str, str],
        body_str: str | None = None,
        path: str = "",
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Extract tenant parameters from all parts of a request.

        Args:
            query_params: URL query parameters.
            body_str: Raw request body string.
            path: URL path.
            headers: HTTP headers dict.

        Returns:
            Dict with tenant_parameters, primary_tenant, is_tenant_aware, etc.
        """
        return extract_tenant_parameters(
            path=path,
            query_params=query_params,
            body=body_str,
            headers=headers,
        )
