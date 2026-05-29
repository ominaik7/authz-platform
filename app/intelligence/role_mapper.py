from collections import defaultdict
from typing import Any


class RoleMapper:
    """
    Tracks relationships between:
    - roles
    - endpoints
    - permissions
    - inferred privilege hierarchy
    """

    def __init__(self) -> None:
        self.role_endpoints: dict[str, set[str]] = defaultdict(set)
        self.endpoint_roles: dict[str, set[str]] = defaultdict(set)
        self.role_permissions: dict[str, set[str]] = defaultdict(set)

        self.endpoint_metadata: dict[str, dict[str, Any]] = {}

    def record_observation(
        self,
        role: str | None,
        method: str,
        path: str,
        permissions: list[str] | None = None,
        endpoint_sensitivity: str | None = None,
    ) -> None:
        """
        Record that a role accessed an endpoint.

        Args:
            role: normalized role name
            method: HTTP method
            path: endpoint path
            permissions: permissions observed in JWT
            endpoint_sensitivity: low/medium/high
        """

        endpoint_key = f"{method.upper()}:{path}"

        # Skip if no role
        if role:
            self.role_endpoints[role].add(endpoint_key)
            self.endpoint_roles[endpoint_key].add(role)

            if permissions:
                self.role_permissions[role].update(permissions)

        # Create endpoint metadata if missing
        if endpoint_key not in self.endpoint_metadata:
            self.endpoint_metadata[endpoint_key] = {
                "method": method.upper(),
                "path": path,
                "sensitivity": endpoint_sensitivity or "unknown",
                "role_count": 0,
                "exclusive_to": None,
            }

        # Update role count
        self.endpoint_metadata[endpoint_key]["role_count"] = len(
            self.endpoint_roles[endpoint_key]
        )

        # Determine exclusivity
        roles_for_endpoint = self.endpoint_roles[endpoint_key]

        if len(roles_for_endpoint) == 1:
            self.endpoint_metadata[endpoint_key]["exclusive_to"] = list(
                roles_for_endpoint
            )[0]
        else:
            self.endpoint_metadata[endpoint_key]["exclusive_to"] = None

    def infer_hierarchy(self) -> dict[str, int]:
        """
        Infer privilege tiers dynamically.

        Higher score means higher privilege.
        """

        scores: dict[str, int] = {}

        for role, endpoints in self.role_endpoints.items():

            endpoint_count = len(endpoints)
            permission_count = len(self.role_permissions.get(role, []))

            score = 0

            # Endpoint coverage
            score += endpoint_count * 5

            # Permission count
            score += permission_count

            # Keyword boosts
            role_lower = role.lower()

            if "super" in role_lower:
                score += 100

            if "platform" in role_lower:
                score += 80

            if "admin" in role_lower:
                score += 50

            if "manager" in role_lower:
                score += 25

            scores[role] = score

        # Normalize scores to 1-100
        if not scores:
            return {}

        max_score = max(scores.values())

        normalized = {}

        for role, score in scores.items():
            normalized_score = int((score / max_score) * 100)

            if normalized_score < 10:
                normalized_score = 10

            normalized[role] = normalized_score

        return normalized

    def get_exclusive_endpoints(self, role: str) -> list[str]:
        """
        Return endpoints only accessed by this role.
        """

        exclusive = []

        for endpoint, roles in self.endpoint_roles.items():
            if len(roles) == 1 and role in roles:
                exclusive.append(endpoint)

        return sorted(exclusive)

    def get_role_tier(self, role: str) -> int:
        """
        Return inferred privilege tier.
        """

        hierarchy = self.infer_hierarchy()

        return hierarchy.get(role, 0)

    def get_stats(self) -> dict[str, Any]:
        """
        Return mapper statistics.
        """

        return {
            "roles": len(self.role_endpoints),
            "endpoints": len(self.endpoint_roles),
            "role_endpoint_associations": sum(
                len(v) for v in self.role_endpoints.values()
            ),
        }

    def get_summary(self) -> dict[str, Any]:
        """
        Return full role intelligence summary.
        """

        hierarchy = self.infer_hierarchy()

        summary: dict[str, Any] = {
            "roles": {},
            "stats": self.get_stats(),
        }

        for role in self.role_endpoints:

            summary["roles"][role] = {
                "tier": hierarchy.get(role, 0),
                "endpoint_count": len(self.role_endpoints[role]),
                "permission_count": len(
                    self.role_permissions.get(role, [])
                ),
                "exclusive_endpoints": self.get_exclusive_endpoints(
                    role
                ),
            }

        # Compatibility flattening for older tests
        for role_name, data in summary["roles"].items():
            summary[role_name] = data

        return summary