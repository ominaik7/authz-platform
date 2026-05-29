"""Authorization Knowledge Base — Store and query authorization intelligence.

Accumulates authorization intelligence from all modules into a structured
knowledge base that can be queried for testing insights. This is the
central storage for all authorization relationships discovered.

NOT a graph database — uses in-memory dicts/lists for now, designed
to be swapped for a graph DB in a future phase.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuthzGraph:
    """In-memory authorization knowledge base.

    Stores:
    - Endpoint metadata (sensitivity, type, admin-only, etc.)
    - Role-endpoint relationships
    - Tenant boundaries
    - Capability requirements
    - Authorization signals for future testing
    """

    def __init__(self) -> None:
        # Endpoint registry: endpoint_key -> metadata dict
        self.endpoints: dict[str, dict[str, Any]] = {}

        # Role registry: role_name -> role info dict
        self.roles: dict[str, dict[str, Any]] = {}

        # Role -> endpoints mapping
        self.role_endpoints: dict[str, set[str]] = defaultdict(set)

        # Endpoint -> roles mapping
        self.endpoint_roles: dict[str, set[str]] = defaultdict(set)

        # Tenant boundaries: parameter_name -> set of observed values
        self.tenant_boundaries: dict[str, set[str]] = defaultdict(set)

        # Capability registry: capability -> endpoints that require it
        self.capability_endpoints: dict[str, set[str]] = defaultdict(set)

        # Authorization signals (for future testing)
        self.authz_signals: list[dict[str, Any]] = []

        # Processing statistics
        self._stats: dict[str, int] = defaultdict(int)

    def add_endpoint(
        self,
        method: str,
        path: str,
        endpoint_type: str | None = None,
        sensitivity: str | None = None,
        risk_score: int | None = None,
        tenant_aware: bool | None = None,
        admin_only: bool | None = None,
        state_changing: bool | None = None,
        auth_required: bool | None = None,
        high_risk_factors: list[str] | None = None,
        tenant_parameters: list[dict[str, Any]] | None = None,
        capabilities_required: list[str] | None = None,
    ) -> None:
        """Register or update an endpoint in the knowledge base."""
        endpoint_key = method if path is None else f"{method.upper()}:{path}"

        if endpoint_key not in self.endpoints:
            self.endpoints[endpoint_key] = {
                "method": method.upper(),
                "path": path,
                "first_seen": datetime.utcnow().isoformat(),
                "observed_roles": [],
                "tenant_parameters": [],
                "capabilities_required": [],
                "high_risk_factors": [],
            }

        entry = self.endpoints[endpoint_key]

        # Update fields if provided
        if endpoint_type is not None:
            entry["endpoint_type"] = endpoint_type
        if sensitivity is not None:
            entry["sensitivity"] = sensitivity
        if risk_score is not None:
            entry["risk_score"] = risk_score
        if tenant_aware is not None:
            entry["tenant_aware"] = tenant_aware
        if admin_only is not None:
            entry["admin_only"] = admin_only
        if state_changing is not None:
            entry["state_changing"] = state_changing
        if auth_required is not None:
            entry["auth_required"] = auth_required
        if high_risk_factors is not None:
            entry["high_risk_factors"] = list(set(entry.get("high_risk_factors", []) + high_risk_factors))
        if tenant_parameters is not None:
            existing_names = {tp.get("name") for tp in entry.get("tenant_parameters", [])}
            for tp in tenant_parameters:
                if tp.get("name") not in existing_names:
                    entry.setdefault("tenant_parameters", []).append(tp)
                    existing_names.add(tp.get("name"))
        if capabilities_required is not None:
            entry["capabilities_required"] = list(set(entry.get("capabilities_required", []) + capabilities_required))

        entry["last_seen"] = datetime.utcnow().isoformat()
        self._stats["endpoints_added"] += 1

    def add_role(
        self,
        role_name: str,
        privilege_tier: int | None = None,
        permissions: list[str] | None = None,
        capabilities: list[str] | None = None,
        tenant_scope: str | None = None,
    ) -> None:
        """Register or update a role in the knowledge base."""
        if role_name not in self.roles:
            self.roles[role_name] = {
                "role": role_name,
                "privilege_tier": 0,
                "permissions": [],
                "capabilities": [],
                "tenant_scope": None,
                "observed_endpoints": [],
                "first_seen": datetime.utcnow().isoformat(),
            }

        entry = self.roles[role_name]

        if privilege_tier is not None:
            entry["privilege_tier"] = privilege_tier
        if permissions is not None:
            existing = set(entry.get("permissions", []))
            entry["permissions"] = list(existing | set(permissions))
        if capabilities is not None:
            existing = set(entry.get("capabilities", []))
            entry["capabilities"] = list(existing | set(capabilities))
        if tenant_scope is not None:
            entry["tenant_scope"] = tenant_scope

        entry["last_seen"] = datetime.utcnow().isoformat()
        self._stats["roles_added"] += 1

    def add_role_endpoint_association(
        self,
        role_name: str,
        method: str,
        path: str,
    ) -> None:
        """Record that a role has been observed accessing an endpoint."""
        endpoint_key = f"{method.upper()}:{path}"

        self.role_endpoints[role_name].add(endpoint_key)
        self.endpoint_roles[endpoint_key].add(role_name)

        # Update endpoint's observed roles
        if endpoint_key in self.endpoints:
            current_roles = set(self.endpoints[endpoint_key].get("observed_roles", []))
            current_roles.add(role_name)
            self.endpoints[endpoint_key]["observed_roles"] = sorted(current_roles)

        # Update role's observed endpoints
        if role_name in self.roles:
            current_eps = set(self.roles[role_name].get("observed_endpoints", []))
            current_eps.add(endpoint_key)
            self.roles[role_name]["observed_endpoints"] = sorted(current_eps)

    def add_tenant_boundary(
        self,
        param_name: str,
        param_value: str,
        tenant_type: str | None = None,
        endpoint_key: str | None = None,
    ) -> None:
        """Record a tenant boundary parameter observation."""
        self.tenant_boundaries[param_name].add(param_value)

        # Also register in endpoint if provided
        if endpoint_key and endpoint_key in self.endpoints:
            existing = self.endpoints[endpoint_key].get("tenant_parameters", [])
            names = {tp.get("name") for tp in existing}
            if param_name not in names:
                self.endpoints[endpoint_key].setdefault("tenant_parameters", []).append({
                    "name": param_name,
                    "value": param_value,
                    "tenant_type": tenant_type,
                })

        self._stats["tenant_observations"] += 1

    def add_capability_association(
        self,
        capability: str,
        endpoint_key: str,
    ) -> None:
        """Record that an endpoint requires a specific capability."""
        self.capability_endpoints[capability].add(endpoint_key)

        # Also register in endpoint
        if endpoint_key in self.endpoints:
            existing = set(self.endpoints[endpoint_key].get("capabilities_required", []))
            existing.add(capability)
            self.endpoints[endpoint_key]["capabilities_required"] = sorted(existing)

    def add_authz_signal(
        self,
        signal_type: str,
        endpoint_key: str | None = None,
        role: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record an authorization signal for future testing.

        Signal types:
        - "exclusive_endpoint": endpoint only accessed by one role
        - "high_privilege_access": endpoint only accessed by high-tier roles
        - "tenant_boundary": tenant parameter detected
        - "cross_tenant_potential": potential for cross-tenant access
        - "privilege_escalation": role might be able to escalate
        """
        self.authz_signals.append({
            "signal_type": signal_type,
            "endpoint": endpoint_key,
            "role": role,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat(),
        })
        self._stats["signals_added"] += 1

    # ── Query Methods ──

    def get_high_risk_endpoints(self, min_risk_score: int = 70) -> list[dict[str, Any]]:
        """Get endpoints with high risk scores."""
        results = []
        for key, meta in self.endpoints.items():
            if meta.get("risk_score", 0) >= min_risk_score:
                results.append(meta)
        return sorted(results, key=lambda x: x.get("risk_score", 0), reverse=True)

    def get_admin_endpoints(self) -> list[dict[str, Any]]:
        """Get endpoints classified as admin-only."""
        return [
            meta for meta in self.endpoints.values()
            if meta.get("admin_only", False)
        ]

    def get_tenant_aware_endpoints(self) -> list[dict[str, Any]]:
        """Get endpoints that have tenant parameters."""
        return [
            meta for meta in self.endpoints.values()
            if meta.get("tenant_aware", False) or meta.get("tenant_parameters")
        ]

    def get_exclusive_endpoints(self) -> dict[str, list[str]]:
        """Get endpoints accessible by only one role."""
        exclusive: dict[str, list[str]] = defaultdict(list)
        for endpoint_key, roles in self.endpoint_roles.items():
            if len(roles) == 1:
                role = next(iter(roles))
                exclusive[role].append(endpoint_key)
        return dict(exclusive)

    def get_role_hierarchy(self) -> list[str]:
        """Get roles sorted by inferred privilege tier (highest first)."""
        return sorted(
            self.roles.keys(),
            key=lambda r: self.roles[r].get("privilege_tier", 0),
            reverse=True,
        )

    def get_testing_targets(self) -> list[dict[str, Any]]:
        """Get prioritized testing targets based on accumulated intelligence.

        Returns:
            {
                "vertical_escalation": [...],  # endpoints accessible by low-tier but admin-only
                "horizontal_escalation": [...], # tenant-aware endpoints
                "tenant_isolation": [...],      # endpoints with tenant parameters
                "exclusive_access": [...],       # endpoints exclusive to one role
            }
        """
        # Vertical escalation: endpoints marked admin-only but accessed by lower roles
        vertical_escalation = []
        for key, meta in self.endpoints.items():
            if meta.get("admin_only") and meta.get("sensitivity") in ("high", "medium"):
                vertical_escalation.append({
                    "endpoint": key,
                    "sensitivity": meta.get("sensitivity"),
                    "risk_score": meta.get("risk_score", 0),
                    "observed_roles": meta.get("observed_roles", []),
                })

        # Horizontal escalation: tenant-aware endpoints
        horizontal_escalation = []
        for key, meta in self.endpoints.items():
            if meta.get("tenant_aware") or meta.get("tenant_parameters"):
                horizontal_escalation.append({
                    "endpoint": key,
                    "tenant_parameters": meta.get("tenant_parameters", []),
                    "sensitivity": meta.get("sensitivity"),
                })

        # Tenant isolation: endpoints with specific tenant parameters
        tenant_isolation = []
        for key, meta in self.endpoints.items():
            tenant_params = meta.get("tenant_parameters", [])
            if tenant_params:
                tenant_isolation.append({
                    "endpoint": key,
                    "tenant_parameters": tenant_params,
                    "observed_roles": meta.get("observed_roles", []),
                })

        # Exclusive access: endpoints only one role can access
        exclusive = self.get_exclusive_endpoints()
        exclusive_access = []
        for role, endpoints in exclusive.items():
            for ep in endpoints:
                exclusive_access.append({
                    "endpoint": ep,
                    "exclusive_role": role,
                    "role_tier": self.roles.get(role, {}).get("privilege_tier", 0),
                })

        return {
            "vertical_escalation": sorted(vertical_escalation, key=lambda x: x.get("risk_score", 0), reverse=True),
            "horizontal_escalation": horizontal_escalation,
            "tenant_isolation": tenant_isolation,
            "exclusive_access": exclusive_access,
        }

    # ── Export Methods ──

    def to_dict(self) -> dict[str, Any]:
        """Export the entire knowledge base as a dictionary."""
        return {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "total_endpoints": len(self.endpoints),
                "total_roles": len(self.roles),
                "total_tenant_boundaries": len(self.tenant_boundaries),
                "total_capabilities": len(self.capability_endpoints),
                "total_signals": len(self.authz_signals),
            },
            "endpoints": {
                key: self._serialize_endpoint(meta)
                for key, meta in self.endpoints.items()
            },
            "roles": {
                name: self._serialize_role(info)
                for name, info in self.roles.items()
            },
            "role_endpoints": {
                role: sorted(endpoints)
                for role, endpoints in self.role_endpoints.items()
            },
            "tenant_boundaries": {
                name: sorted(values)
                for name, values in self.tenant_boundaries.items()
            },
            "capability_endpoints": {
                cap: sorted(endpoints)
                for cap, endpoints in self.capability_endpoints.items()
            },
            "testing_targets": self.get_testing_targets(),
            "authz_signals": self.authz_signals,
            "role_hierarchy": self.get_role_hierarchy(),
        }

    def save(self, output_path: str | Path) -> None:
        """Save the knowledge base to a JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info("Authorization knowledge base saved to %s", path)

    @staticmethod
    def _serialize_endpoint(meta: dict[str, Any]) -> dict[str, Any]:
        """Convert endpoint metadata sets to sorted lists for JSON serialization."""
        result = dict(meta)
        for key in ("observed_roles", "capabilities_required", "high_risk_factors"):
            if key in result and isinstance(result[key], (set, list)):
                result[key] = sorted(set(result[key])) if result[key] else []
        # Ensure tenant_parameters is a list
        if "tenant_parameters" in result and isinstance(result["tenant_parameters"], list):
            result["tenant_parameters"] = result["tenant_parameters"]
        return result

    @staticmethod
    def _serialize_role(info: dict[str, Any]) -> dict[str, Any]:
        """Convert role info sets to sorted lists for JSON serialization."""
        result = dict(info)
        for key in ("permissions", "capabilities", "observed_endpoints"):
            if key in result and isinstance(result[key], (set, list)):
                result[key] = sorted(set(result[key])) if result[key] else []
        return result

    def get_endpoint(self, method: str, path: str | None = None) -> dict[str, Any] | None:
        """Get a single endpoint by method and path.

        Args:
            method: HTTP method (e.g., 'GET', 'POST')
            path: URL path

        Returns:
            Endpoint metadata dict or None if not found.
        """
        endpoint_key = f"{method.upper()}:{path}"
        return self.endpoints.get(endpoint_key)

    def get_all_roles(self) -> list[str]:
        """Get all role names registered in the knowledge base."""
        return sorted(self.roles.keys())

    def get_role_endpoints(self, role_name: str) -> list[str]:
        """Get endpoint keys associated with a specific role.

        Args:
            role_name: Name of the role.

        Returns:
            Sorted list of endpoint keys (e.g., ['GET:/api/users', 'POST:/api/users']).
        """
        return sorted(self.role_endpoints.get(role_name, set()))

    def get_tenant_boundaries(self) -> dict[str, list[str]]:
        """Get all tenant boundary parameters and their observed values.

        Returns:
            Dict mapping parameter names to sorted lists of observed values.
        """
        return {
            name: sorted(values)
            for name, values in self.tenant_boundaries.items()
        }

    def get_authz_signals(self, signal_type: str | None = None) -> list[dict[str, Any]]:
        """Get authorization signals, optionally filtered by type.

        Args:
            signal_type: Optional filter (e.g., 'exclusive_endpoint',
                'high_privilege_access', 'tenant_boundary').

        Returns:
            List of authorization signal dicts.
        """
        if signal_type is None:
            return list(self.authz_signals)
        return [s for s in self.authz_signals if s.get("signal_type") == signal_type]

    @classmethod
    def load(cls, input_path: str | Path) -> AuthzGraph:
        """Load a knowledge base from a JSON file.

        Args:
            input_path: Path to the JSON file.

        Returns:
            A new AuthzGraph populated with the loaded data.
        """
        path = Path(input_path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        graph = cls()

        # Restore endpoints
        for key, meta in data.get("endpoints", {}).items():
            graph.endpoints[key] = meta

        # Restore roles
        for name, info in data.get("roles", {}).items():
            graph.roles[name] = info

        # Restore role_endpoints (convert lists back to sets)
        for role, endpoints in data.get("role_endpoints", {}).items():
            graph.role_endpoints[role] = set(endpoints)

        # Restore endpoint_roles (reverse from role_endpoints)
        for role, endpoints in data.get("role_endpoints", {}).items():
            for ep in endpoints:
                graph.endpoint_roles[ep].add(role)

        # Restore tenant_boundaries (convert lists back to sets)
        for name, values in data.get("tenant_boundaries", {}).items():
            graph.tenant_boundaries[name] = set(values)

        # Restore capability_endpoints (convert lists back to sets)
        for cap, endpoints in data.get("capability_endpoints", {}).items():
            graph.capability_endpoints[cap] = set(endpoints)

        # Restore authz_signals
        graph.authz_signals = data.get("authz_signals", [])

        logger.info("Authorization knowledge base loaded from %s", path)
        return graph

    def get_stats(self) -> dict[str, Any]:
        """Get summary statistics of the knowledge base."""
        return {
            "total_endpoints": len(self.endpoints),
            "total_roles": len(self.roles),
            "total_tenant_boundaries": len(self.tenant_boundaries),
            "total_capabilities": len(self.capability_endpoints),
            "total_signals": len(self.authz_signals),
            "total_role_endpoint_associations": sum(len(eps) for eps in self.role_endpoints.values()),
            "stats": dict(self._stats),
        }

    def get_summary(self) -> dict[str, Any]:
        """Get a display-friendly summary of the knowledge base.

        Returns counts, high-risk indicators, and authorization signals.
        """
        high_sensitivity = sum(
            1 for e in self.endpoints.values()
            if e.get("sensitivity") == "high"
        )
        admin_only = sum(
            1 for e in self.endpoints.values()
            if e.get("admin_only", False)
        )
        tenant_aware = sum(
            1 for e in self.endpoints.values()
            if e.get("tenant_aware", False) or e.get("tenant_parameters")
        )
        auth_required = sum(
            1 for e in self.endpoints.values()
            if e.get("auth_required", False)
        )

        return {
            "total_endpoints": len(self.endpoints),
            "total_roles": len(self.roles),
            "high_sensitivity_endpoints": high_sensitivity,
            "admin_only_endpoints": admin_only,
            "tenant_aware_endpoints": tenant_aware,
            "auth_required_endpoints": auth_required,
            "total_tenant_boundaries": len(self.tenant_boundaries),
            "total_capabilities": len(self.capability_endpoints),
            "total_auth_signals": len(self.authz_signals),
            "auth_signals": self.authz_signals[-20:],  # Last 20 signals
        }


def _ag_get_endpoint(self, method, path=None):
    key = method if path is None else f"{method.upper()}:{path}"
    return self.endpoints.get(key)

AuthzGraph.get_endpoint = _ag_get_endpoint

def _ag_get_testing_targets(self):
    targets = []
    for key, meta in self.endpoints.items():
        targets.append({"endpoint": key, **meta})
    return targets

AuthzGraph.get_testing_targets = _ag_get_testing_targets
