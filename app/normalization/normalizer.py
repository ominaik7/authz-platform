"""Normalizer — converts raw traffic into structured, deduplicated HTTPTransaction objects."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from ..auth.jwt_decoder import JWTDecoder
from ..auth.capability_mapper import CapabilityMapper
from ..auth.tenant_extractor import TenantExtractor
from ..intelligence.endpoint_classifier import EndpointClassifier
from ..intelligence.role_mapper import RoleMapper
from ..models.request_model import HTTPTransaction, RequestModel, ResourceID, ResponseModel
from ..parsers.burp_xml_parser import RawTrafficItem
from ..parsers.filters import (
    FilterResult,
    detect_content_type_category,
    is_api_candidate,
    should_filter_request,
)
from ..parsers.raw_http_parser import ParsedRequest, ParsedResponse, parse_raw_request, parse_raw_response
from ..storage.authz_graph import AuthzGraph
from .extractor import extract_resource_ids

logger = logging.getLogger(__name__)


class NormalizationResult:
    """Result of the full normalization pipeline."""

    def __init__(self) -> None:
        self.transactions: list[HTTPTransaction] = []
        self.total_parsed: int = 0
        self.filtered_count: int = 0
        self.filtered_reasons: dict[str, int] = {}
        self.duplicate_count: int = 0
        self.api_candidates: int = 0
        self.unique_resource_ids: int = 0
        self.decode_errors: int = 0
        self._resource_id_set: set[tuple[str, str]] = set()
        # Authorization intelligence modules
        self.jwt_decoder = JWTDecoder()
        self.capability_mapper = CapabilityMapper()
        self.tenant_extractor = TenantExtractor()
        self.endpoint_classifier = EndpointClassifier()
        self.role_mapper = RoleMapper()
        self.authz_graph = AuthzGraph()
        # Auth stats
        self.jwt_tokens_found: int = 0
        self.tenant_params_found: int = 0
        self.capabilities_mapped: int = 0

    def add_filtered(self, reason: str) -> None:
        """Track a filtered-out request."""
        self.filtered_count += 1
        self.filtered_reasons[reason] = self.filtered_reasons.get(reason, 0) + 1

    def add_resource_ids(self, ids: list[ResourceID]) -> None:
        """Track unique resource IDs."""
        for rid in ids:
            key = (rid.type, rid.value)
            self._resource_id_set.add(key)
        self.unique_resource_ids = len(self._resource_id_set)


def compute_fingerprint(method: str, path: str, headers: dict[str, str], body: str | None) -> str:
    """Compute a SHA256 fingerprint for request deduplication.

    Fingerprint formula:
        SHA256(method + normalized_path + sorted_headers + body)

    The path is normalized by removing resource IDs so that
    /api/users/1 and /api/users/2 share the same fingerprint.
    """
    # Normalize path by replacing numeric/UUID/Mongo ID segments
    normalized_path = _normalize_path(path)

    # Sort headers for deterministic ordering
    sorted_headers = json.dumps(
        dict(sorted(headers.items())),
        separators=(",", ":"),
    )

    body_str = body or ""

    fingerprint_input = f"{method}|{normalized_path}|{sorted_headers}|{body_str}"
    return hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()


def normalize_traffic(items: list[RawTrafficItem]) -> NormalizationResult:
    """Full normalization pipeline: parse → filter → extract → deduplicate → model.

    Args:
        items: List of RawTrafficItem from Burp XML parser.

    Returns:
        NormalizationResult with transactions, stats, and metadata.
    """
    result = NormalizationResult()
    seen_fingerprints: set[str] = set()

    for idx, item in enumerate(items):
        result.total_parsed += 1

        # Track decode errors
        if item.decode_errors:
            result.decode_errors += len(item.decode_errors)

        # Parse raw HTTP
        parsed_req = parse_raw_request(item.raw_request, url_hint=item.url)
        parsed_resp = parse_raw_response(item.raw_response)

        # If method was not parsed from raw request, use Burp metadata
        if not parsed_req.method and item.method:
            parsed_req.method = item.method

        # If URL was not reconstructed, use Burp metadata
        if not parsed_req.full_url and item.url:
            parsed_req.full_url = item.url

        # Filter noise
        filter_result = should_filter_request(
            path=parsed_req.path,
            content_type=parsed_resp.content_type,
            method=parsed_req.method,
            url=parsed_req.full_url,
        )

        if not filter_result.passed:
            result.add_filtered(filter_result.reason)
            logger.debug(
                "Filtered request %s %s: %s",
                parsed_req.method,
                parsed_req.path,
                filter_result.reason,
                extra={
                    "request_id": f"raw_{idx:03d}",
                    "parser_stage": "filter",
                    "filtered_reason": filter_result.reason,
                },
            )
            continue

        # Build request ID
        req_id = f"req_{idx + 1:03d}"

        # Compute fingerprint
        fingerprint = compute_fingerprint(
            parsed_req.method,
            parsed_req.path,
            parsed_req.headers,
            parsed_req.body if parsed_req.body else None,
        )

        # Deduplication
        if fingerprint in seen_fingerprints:
            result.duplicate_count += 1
            logger.debug(
                "Duplicate request skipped: %s %s",
                parsed_req.method,
                parsed_req.path,
                extra={
                    "request_id": req_id,
                    "parser_stage": "dedup",
                },
            )
            continue
        seen_fingerprints.add(fingerprint)

        # Extract resource IDs
        resource_ids = extract_resource_ids(
            parsed_req.path,
            parsed_req.body if parsed_req.body else None,
        )
        result.add_resource_ids(resource_ids)

        # Determine API candidate
        api_candidate = is_api_candidate(
            content_type=parsed_resp.content_type,
            path=parsed_req.path,
            method=parsed_req.method,
        )
        if api_candidate:
            result.api_candidates += 1

        # Detect content type category
        ct_category = detect_content_type_category(parsed_resp.content_type)

        # Build Pydantic models
        request_model = RequestModel(
            id=req_id,
            method=parsed_req.method,
            url=parsed_req.full_url,
            path=parsed_req.path,
            headers=parsed_req.headers,
            query_params=parsed_req.query_params,
            cookies=parsed_req.cookies,
            body=parsed_req.body if parsed_req.body else None,
        )

        response_model = ResponseModel(
            status_code=parsed_resp.status_code,
            headers=parsed_resp.headers,
            body=parsed_resp.body if parsed_resp.body else None,
            content_type=parsed_resp.content_type,
        )

        # Build metadata
        metadata: dict[str, Any] = {
            "resource_ids": [
                {
                    "type": rid.type,
                    "value": rid.value,
                    "location": rid.location,
                }
                for rid in resource_ids
            ],
            "api_candidate": api_candidate,
            "fingerprint": fingerprint,
            "content_type_category": ct_category,
            "mimetype": item.mimetype,
            "host": item.host or parsed_req.host,
            "port": item.port,
            "protocol": item.protocol,
            "time": item.time,
            "comment": item.comment,
        }

        # Check for XHR/fetch indicator (Accept header containing json)
        accept_header = parsed_req.headers.get("Accept", "")
        if accept_header and "application/json" in accept_header.lower():
            metadata["xhr_indicator"] = True

        # ── Authorization Intelligence Pipeline ──

        # 1. JWT decoding → identity context
        identity_context = None
        jwt_result = result.jwt_decoder.decode_from_headers(parsed_req.headers)
        if jwt_result:
            identity_context = result.jwt_decoder.build_identity_context(jwt_result)
            result.jwt_tokens_found += 1

        # 2. Capability mapping from JWT permissions
        authorization_context = None
        capabilities = []
        if jwt_result and jwt_result.get("permissions"):
            capabilities = result.capability_mapper.map_permissions(jwt_result["permissions"])
        elif identity_context and identity_context.get("permissions"):
            capabilities = result.capability_mapper.map_permissions(identity_context["permissions"])

        # 3. Tenant extraction from query params, body, and path
        tenant_result = result.tenant_extractor.extract_from_request(
            query_params=parsed_req.query_params,
            body_str=parsed_req.body,
            path=parsed_req.path,
        )
        tenant_params = tenant_result.get("tenant_parameters", []) if tenant_result else []

        if tenant_params:
            result.tenant_params_found += len(tenant_params)

        # Build authorization context
        if identity_context or capabilities or tenant_params:
            tenant_scope = "unknown"
            if identity_context:
                tenant_scope = identity_context.get("tenant_scope", "unknown")
            authorization_context = {
                "tenant_parameters": tenant_params,
                "capabilities": capabilities,
                "tenant_scope": tenant_scope,
            }
            if capabilities:
                result.capabilities_mapped += len(capabilities)

        # 4. Endpoint classification
        endpoint_metadata = result.endpoint_classifier.classify(
            method=parsed_req.method,
            path=parsed_req.path,
            identity_context=identity_context,
            request_body=parsed_req.body,
        )

        # 5. Enrich request model with auth context
        request_model.identity_context = identity_context
        request_model.authorization_context = authorization_context
        request_model.endpoint_metadata = endpoint_metadata

        # 6. Update role mapper and authz graph
        endpoint_key = f"{parsed_req.method.upper()}:{parsed_req.path}"
        role_name = None

        if identity_context:
            role_name = identity_context.get("role")
            if role_name:
                # Register role in role mapper
                result.role_mapper.record_observation(
                    role=role_name,
                    method=parsed_req.method,
                    path=parsed_req.path,
                    permissions=identity_context.get("permissions"),
                    endpoint_sensitivity=endpoint_metadata.get("sensitivity") if endpoint_metadata else None,
                )

        # Register endpoint in authz graph
        result.authz_graph.add_endpoint(
            method=parsed_req.method,
            path=parsed_req.path,
            endpoint_type=endpoint_metadata.get("endpoint_type") if endpoint_metadata else None,
            sensitivity=endpoint_metadata.get("sensitivity") if endpoint_metadata else None,
            risk_score=endpoint_metadata.get("risk_score") if endpoint_metadata else None,
            tenant_aware=endpoint_metadata.get("tenant_aware") if endpoint_metadata else None,
            admin_only=endpoint_metadata.get("admin_only") if endpoint_metadata else None,
            state_changing=endpoint_metadata.get("state_changing") if endpoint_metadata else None,
            auth_required=identity_context is not None,
            high_risk_factors=endpoint_metadata.get("high_risk_factors") if endpoint_metadata else None,
        )

        # Register role-endpoint association
        if role_name:
            result.authz_graph.add_role(
                role_name=role_name,
                privilege_tier=identity_context.get("privilege_tier") if identity_context else None,
                capabilities=capabilities or None,
                tenant_scope=identity_context.get("tenant_scope") if identity_context else None,
            )
            result.authz_graph.add_role_endpoint_association(
                role_name=role_name,
                method=parsed_req.method,
                path=parsed_req.path,
            )

        # Register tenant boundaries in authz graph
        for tp in tenant_params:
            result.authz_graph.add_tenant_boundary(
                param_name=tp["name"],
                param_value=tp["value"],
                tenant_type=tp["tenant_type"],
                endpoint_key=endpoint_key,
            )

        # Register capability associations
        for cap in capabilities:
            result.authz_graph.add_capability_association(
                capability=cap,
                endpoint_key=endpoint_key,
            )

        # Generate authorization signals
        if endpoint_metadata and endpoint_metadata.get("admin_only") and identity_context:
            tier = identity_context.get("privilege_tier", 0)
            if tier < 50:
                result.authz_graph.add_authz_signal(
                    signal_type="potential_vertical_escalation",
                    endpoint_key=endpoint_key,
                    role=role_name,
                    details={"privilege_tier": tier, "admin_only": True},
                )

        if tenant_params and identity_context:
            result.authz_graph.add_authz_signal(
                signal_type="tenant_boundary_detected",
                endpoint_key=endpoint_key,
                role=role_name,
                details={"tenant_params": [tp["name"] for tp in tenant_params]},
            )

        # ── End Authorization Intelligence Pipeline ──

        transaction = HTTPTransaction(
            request=request_model,
            response=response_model,
            metadata=metadata,
        )

        result.transactions.append(transaction)

    logger.info(
        "Normalization complete: %d parsed, %d filtered, %d duplicates, %d retained, %d API candidates",
        result.total_parsed,
        result.filtered_count,
        result.duplicate_count,
        len(result.transactions),
        result.api_candidates,
        extra={"parser_stage": "normalization"},
    )

    return result


def _normalize_path(path: str) -> str:
    """Normalize a URL path by replacing resource ID segments with placeholders.

    /api/users/1 → /api/users/{id}
    /api/orgs/550e8400-e29b-41d4-a716-446655440000 → /api/orgs/{id}
    /api/items/507f1f77bcf86cd799439011 → /api/items/{id}
    """
    import re

    # Replace numeric IDs
    normalized = re.sub(r"(?<=/)\d{1,20}(?=/|$)", "{id}", path)

    # Replace UUIDs
    normalized = re.sub(
        r"(?<=/)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)",
        "{id}",
        normalized,
        flags=re.IGNORECASE,
    )

    # Replace Mongo IDs
    normalized = re.sub(
        r"(?<=/)[0-9a-fA-F]{24}(?=/|$)",
        "{id}",
        normalized,
        flags=re.IGNORECASE,
    )

    return normalized