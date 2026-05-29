"""Capability Mapping Engine — Converts noisy permissions into semantic capabilities.

Groups granular permissions like PortalInstitute_Create, PortalInstitute_Modify
into higher-level capabilities like manage_institutes.

This module builds the WHAT dimension of authorization intelligence.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Permission Pattern Extraction ──

# Common separators in permission strings
PERM_SEPARATORS = re.compile(r"[_\-\.:]+")


# ── Capability Aggregation Rules ──

# Action keywords that map to capability levels
ACTION_KEYWORDS: dict[str, str] = {
    "create": "manage",
    "add": "manage",
    "insert": "manage",
    "modify": "manage",
    "update": "manage",
    "edit": "manage",
    "delete": "manage",
    "remove": "manage",
    "read": "view",
    "view": "view",
    "list": "view",
    "get": "view",
    "search": "view",
    "export": "view",
    "download": "view",
    "approve": "manage",
    "reject": "manage",
    "assign": "manage",
    "revoke": "manage",
    "publish": "manage",
    "unpublish": "manage",
    "activate": "manage",
    "deactivate": "manage",
    "enable": "manage",
    "disable": "manage",
    "reset": "manage",
    "configure": "configure",
    "config": "configure",
    "manage": "manage",
    "admin": "admin",
    "administer": "admin",
}

# Resource keywords that map to capability domains
RESOURCE_KEYWORDS: dict[str, str] = {
    "user": "users",
    "users": "users",
    "account": "users",
    "accounts": "users",
    "member": "users",
    "members": "users",
    "profile": "users",
    "institute": "institutes",
    "institutes": "institutes",
    "school": "institutes",
    "schools": "institutes",
    "organization": "organizations",
    "organizations": "organizations",
    "org": "organizations",
    "tenant": "tenants",
    "tenants": "tenants",
    "role": "roles",
    "roles": "roles",
    "permission": "permissions_config",
    "permissions": "permissions_config",
    "privilege": "permissions_config",
    "course": "courses",
    "courses": "courses",
    "class": "classes",
    "classes": "classes",
    "student": "students",
    "students": "students",
    "teacher": "teachers",
    "teachers": "teachers",
    "report": "reporting",
    "reports": "reporting",
    "dashboard": "reporting",
    "analytics": "reporting",
    "statistics": "reporting",
    "billing": "billing",
    "payment": "billing",
    "payments": "billing",
    "invoice": "billing",
    "subscription": "billing",
    "setting": "settings",
    "settings": "settings",
    "config": "settings",
    "configuration": "settings",
    "preference": "settings",
    "notification": "notifications",
    "notifications": "notifications",
    "email": "notifications",
    "audit": "audit",
    "log": "audit",
    "logs": "audit",
    "content": "content",
    "media": "content",
    "file": "content",
    "files": "content",
    "document": "content",
    "task": "tasks",
    "tasks": "tasks",
    "assignment": "tasks",
    "exam": "exams",
    "exams": "exams",
    "quiz": "exams",
    "assessment": "exams",
    "certificate": "certificates",
    "certificates": "certificates",
    "credential": "certificates",
}

# Admin-level capability keywords — these override normal mapping
ADMIN_RESOURCE_KEYWORDS: dict[str, str] = {
    "system": "manage_users",
    "platform": "platform_admin",
    "global": "global_admin",
    "super": "super_admin",
}


def map_permissions_to_capabilities(permissions: list[str]) -> dict[str, Any]:
    """Convert a list of raw permissions into semantic capabilities.

    Example input:
        ["PortalInstitute_Create", "PortalInstitute_Modify", "PortalInstitute_Delete"]

    Example output:
        {
            "capabilities": ["manage_institutes"],
            "action_coverage": {"manage": 3, "view": 0},
            "raw_permissions": 3,
            "capability_domains": ["institutes"]
        }
    """
    if not permissions:
        return {
            "capabilities": [],
            "action_coverage": {},
            "raw_permissions": 0,
            "capability_domains": [],
        }

    # Track capabilities and action coverage
    capabilities: set[str] = set()
    action_coverage: dict[str, int] = {}
    domains: set[str] = set()

    for perm in permissions:
        perm_str = str(perm).strip()
        if not perm_str:
            continue

        # Parse the permission into action + resource
        action, resource = _parse_permission(perm_str)

        # Map action to capability level
        capability_action = ACTION_KEYWORDS.get(action.lower(), "access")

        # Map resource to capability domain
        capability_domain = _map_resource_to_domain(resource)

        # Check for admin-level capabilities
        admin_domain = _check_admin_resource(resource)

        if admin_domain:
            capabilities.add(admin_domain)
            domains.add(admin_domain.replace("_admin", ""))
        else:
            cap = f"{capability_action}_{capability_domain}"
            capabilities.add(cap)
            domains.add(capability_domain)

        # Track action coverage
        action_coverage[capability_action] = action_coverage.get(capability_action, 0) + 1

    return {
        "capabilities": sorted(capabilities),
        "action_coverage": action_coverage,
        "raw_permissions": len(permissions),
        "capability_domains": sorted(domains),
    }


def _parse_permission(perm: str) -> tuple[str, str]:
    """Parse a permission string into (action, resource) components.

    Handles formats like:
        PortalInstitute_Create → (Create, PortalInstitute)
        user:create → (create, user)
        users.read → (read, users)
        ROLE_ADMIN → (admin, role)
    """
    # Try splitting by common separators
    parts = PERM_SEPARATORS.split(perm)

    if len(parts) >= 2:
        # Convention: Resource_Action or action_resource or resource:action
        # Heuristic: if the last part looks like an action, use it
        last = parts[-1].lower()
        first = parts[0].lower()

        if last in ACTION_KEYWORDS or last in {"create", "read", "update", "delete", "modify", "manage", "view", "list", "get", "add", "edit", "remove"}:
            action = last
            resource = "_".join(parts[:-1])
        elif first in ACTION_KEYWORDS or first in {"create", "read", "update", "delete", "modify", "manage", "view", "list", "get", "add", "edit", "remove"}:
            action = first
            resource = "_".join(parts[1:])
        else:
            # Default: last segment is action
            action = last
            resource = "_".join(parts[:-1]) if len(parts) > 1 else perm

        return action, resource

    # Single word — treat as resource with generic action
    return "access", perm


def _map_resource_to_domain(resource: str) -> str:
    """Map a resource string to a capability domain.

    Example: PortalInstitute → institutes
    """
    resource_lower = resource.lower()

    # Direct match
    if resource_lower in RESOURCE_KEYWORDS:
        return RESOURCE_KEYWORDS[resource_lower]

    # Partial match — check if any keyword is contained in the resource
    for keyword, domain in RESOURCE_KEYWORDS.items():
        if keyword in resource_lower:
            return domain

    # CamelCase / PascalCase splitting
    words = re.sub(r"([A-Z])", r"_\1", resource).split("_")
    words = [w.lower() for w in words if w]

    for word in words:
        if word in RESOURCE_KEYWORDS:
            return RESOURCE_KEYWORDS[word]

    # Fallback: use the last meaningful word
    if words:
        return words[-1] + "s" if not words[-1].endswith("s") else words[-1]

    return resource_lower


def _check_admin_resource(resource: str) -> str | None:
    """Check if a resource indicates admin-level capability.

    Returns the admin capability domain if found, None otherwise.
    """
    resource_lower = resource.lower()

    for keyword, admin_cap in ADMIN_RESOURCE_KEYWORDS.items():
        if keyword in resource_lower:
            return admin_cap

    return None


def infer_capabilities_from_permissions(permissions: list[str]) -> list[str]:
    """Simplified API: return just the capability list from permissions."""
    result = map_permissions_to_capabilities(permissions)
    return result["capabilities"]


class CapabilityMapper:
    """Stateless wrapper for capability mapping functions.

    Provides an object-oriented interface matching the NormalizationResult
    pipeline convention while delegating to module-level functions.
    """

    def map_permissions(self, permissions: list[str] | None) -> list[str]:
        """Map permissions to semantic capabilities.

        Args:
            permissions: List of raw permission strings. None is treated as empty.

        Returns:
            List of semantic capability strings.
        """
        if permissions is None:
            return []
        return infer_capabilities_from_permissions(permissions)

    def infer_capability_tier(self, capabilities: list[str]) -> int:
        """Infer a privilege tier score (0-100) from a list of capabilities.

        Uses heuristics based on:
        - Number of capabilities (more = higher privilege)
        - Presence of admin-level capabilities
        - Presence of manage vs view capabilities
        - Domain coverage breadth

        Args:
            capabilities: List of semantic capability strings.

        Returns:
            Integer privilege tier score from 0 to 100.
        """
        if not capabilities:
            return 0

        score = 0

        # Base score from number of capabilities
        cap_count = len(capabilities)
        if cap_count >= 20:
            score = max(score, 70)
        elif cap_count >= 10:
            score = max(score, 50)
        elif cap_count >= 5:
            score = max(score, 30)
        elif cap_count >= 1:
            score = max(score, 10)

        # Check for admin-level capabilities
        for cap in capabilities:
            cap_lower = cap.lower()
            if "admin" in cap_lower:
                score = max(score, 90)
            elif "system" in cap_lower or "platform" in cap_lower:
                score = max(score, 80)
            elif "manage" in cap_lower:
                score = max(score, 40)
            elif "configure" in cap_lower:
                score = max(score, 50)

        # Ensure minimum score if we have any capabilities
        if capabilities:
            score = max(score, 5)

        return min(score, 100)


def _normalize_plural(word: str) -> str:
    if word.endswith("ies"):
        return word[:-3] + "y"
    if word.endswith("ys"):
        return word[:-2] + "ies"
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word
