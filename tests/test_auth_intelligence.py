"""Tests for the Authorization Intelligence Layer (Phase 1.5).

Covers: JWT decoding, capability mapping, tenant extraction,
endpoint classification, role mapping, and the authorization graph.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile

import pytest

from app.auth.jwt_decoder import (
    JWTDecoder,
    decode_jwt_payload,
    detect_jwt_in_headers,
    infer_privilege_tier,
    normalize_role_name,
)
from app.auth.capability_mapper import CapabilityMapper
from app.auth.tenant_extractor import TenantExtractor
from app.intelligence.endpoint_classifier import EndpointClassifier
from app.intelligence.role_mapper import RoleMapper
from app.storage.authz_graph import AuthzGraph


# ── Helpers ──


def _make_jwt(payload: dict | None = None, header: dict | None = None) -> str:
    """Create a JWT token string (unsigned, for testing)."""
    if header is None:
        header = {"alg": "HS256"}
    if payload is None:
        payload = {
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Platform Admin",
            "prms": [
                "PRM_1_PortalInstitute_Create",
                "PRM_1_PortalInstitute_Modify",
            ],
            "nameidentifier": "663c79ef001f1f13fa5dbba4",
            "RoleId": "62d657368570ac2e66028c2e",
        }
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.fake_signature"


def _make_bearer_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── JWT Decoder Tests ──


class TestJWTDecoder:
    SAMPLE_JWT_PAYLOAD = {
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Platform Admin",
        "prms": [
            "PRM_1_PortalInstitute_Create",
            "PRM_1_PortalInstitute_Modify",
        ],
        "nameidentifier": "663c79ef001f1f13fa5dbba4",
        "RoleId": "62d657368570ac2e66028c2e",
    }

    def test_decode_valid_jwt(self) -> None:
        token = _make_jwt()
        claims = decode_jwt_payload(token)
        assert isinstance(claims, dict)
        assert "prms" in claims

    def test_decode_invalid_jwt(self) -> None:
        claims = decode_jwt_payload("not.a.valid.jwt.token.format")
        assert claims == {}

    def test_decode_empty_string(self) -> None:
        claims = decode_jwt_payload("")
        assert claims == {}

    def test_extract_identity_context(self) -> None:
        token = _make_jwt()
        headers = _make_bearer_header(token)
        decoder = JWTDecoder()
        jwt_result = decoder.decode_from_headers(headers)
        assert jwt_result is not None
        context = decoder.build_identity_context(jwt_result)
        assert context is not None
        assert context["role"] == "platform_admin"
        assert context["privilege_tier"] > 0

    def test_extract_identity_no_token(self) -> None:
        decoder = JWTDecoder()
        result = decoder.decode_from_headers({"Content-Type": "application/json"})
        assert result is None

    def test_normalize_role_names(self) -> None:
        assert normalize_role_name("Platform Admin") == "platform_admin"
        assert normalize_role_name("Institute Admin") == "institute_admin"
        assert normalize_role_name("Super Admin") == "super_admin"

    def test_infer_privilege_tier(self) -> None:
        claims = self.SAMPLE_JWT_PAYLOAD.copy()
        tier = infer_privilege_tier("platform_admin", claims.get("prms"))
        assert tier >= 80

    def test_infer_privilege_tier_low_role(self) -> None:
        tier = infer_privilege_tier("viewer", ["PRM_1_View_Something"])
        assert tier < 50

    def test_detect_bearer_token(self) -> None:
        token = _make_jwt({"role": "admin"})
        headers = _make_bearer_header(token)
        result = detect_jwt_in_headers(headers)
        assert result is not None

    def test_no_bearer_token(self) -> None:
        headers = {"Content-Type": "application/json"}
        result = detect_jwt_in_headers(headers)
        assert result is None

    def test_tenant_from_claims(self) -> None:
        decoder = JWTDecoder()
        claims = {
            "nameidentifier": "663c79ef001f1f13fa5dbba4",
            "iss": "https://uat.housing360.co.in/",
        }
        context = decoder.build_identity_context(claims)
        # No tenant claim → global scope
        assert context is not None
        assert context["tenant_scope"] == "global"


# ── Capability Mapper Tests ──


class TestCapabilityMapper:
    def test_map_portal_institute_permissions(self) -> None:
        mapper = CapabilityMapper()
        permissions = [
            "PortalInstitute_Create",
            "PortalInstitute_Modify",
            "PortalInstitute_Delete",
        ]
        result = mapper.map_permissions(permissions)
        assert "manage_institutes" in result

    def test_map_user_permissions(self) -> None:
        mapper = CapabilityMapper()
        permissions = ["SystemUser_Create", "SystemUser_Modify"]
        result = mapper.map_permissions(permissions)
        assert "manage_users" in result

    def test_map_prm_prefixed_permissions(self) -> None:
        mapper = CapabilityMapper()
        permissions = [
            "PRM_1_PortalInstitute_Create",
            "PRM_1_PortalInstitute_Modify",
        ]
        result = mapper.map_permissions(permissions)
        assert "manage_institutes" in result

    def test_empty_permissions(self) -> None:
        mapper = CapabilityMapper()
        result = mapper.map_permissions([])
        assert result == []

    def test_none_permissions(self) -> None:
        mapper = CapabilityMapper()
        result = mapper.map_permissions(None)
        assert result == []

    def test_capability_tier_inference(self) -> None:
        mapper = CapabilityMapper()
        caps = mapper.map_permissions([
            "PortalInstitute_Create",
            "SystemUser_Create",
            "PortalReport_View",
        ])
        tier = mapper.infer_capability_tier(caps)
        assert tier > 0

    def test_unmapped_permissions_tracked(self) -> None:
        mapper = CapabilityMapper()
        result = mapper.map_permissions(["SomeRandomPermission_XYZ"])
        # Should still return something (generic or unmapped tracking)
        assert isinstance(result, list)


# ── Tenant Extractor Tests ──


class TestTenantExtractor:
    def test_detect_institute_id(self) -> None:
        ext = TenantExtractor()
        result = ext.extract_from_request(
            query_params={"instituteId": "64e85a..."},
            body_str=None,
            path="/api/data",
        )
        tenant_params = result.get("tenant_parameters", [])
        assert len(tenant_params) >= 1
        names = [tp["name"] for tp in tenant_params]
        assert "instituteId" in names

    def test_detect_organization_id(self) -> None:
        ext = TenantExtractor()
        result = ext.extract_from_request(
            query_params={"organizationId": "org-123"},
            body_str=None,
            path="/api/data",
        )
        tenant_params = result.get("tenant_parameters", [])
        assert len(tenant_params) >= 1
        names = [tp["name"] for tp in tenant_params]
        assert "organizationId" in names

    def test_detect_tenant_id(self) -> None:
        ext = TenantExtractor()
        result = ext.extract_from_request(
            query_params={"tenantId": "t-456"},
            body_str=None,
            path="/api/data",
        )
        tenant_params = result.get("tenant_parameters", [])
        assert len(tenant_params) >= 1
        names = [tp["name"] for tp in tenant_params]
        assert "tenantId" in names

    def test_no_tenant_params(self) -> None:
        ext = TenantExtractor()
        result = ext.extract_from_request(
            query_params={"page": "1", "search": "test"},
            body_str=None,
            path="/api/data",
        )
        tenant_params = result.get("tenant_parameters", [])
        assert len(tenant_params) == 0

    def test_detect_from_body(self) -> None:
        ext = TenantExtractor()
        body = json.dumps({"instituteId": "64e85a...", "name": "Test"})
        result = ext.extract_from_request(
            query_params={},
            body_str=body,
            path="/api/data",
        )
        tenant_params = result.get("tenant_parameters", [])
        assert len(tenant_params) >= 1
        names = [tp["name"] for tp in tenant_params]
        assert "instituteId" in names

    def test_detect_from_empty_body(self) -> None:
        ext = TenantExtractor()
        result = ext.extract_from_request(
            query_params={},
            body_str=None,
            path="/api/data",
        )
        tenant_params = result.get("tenant_parameters", [])
        assert len(tenant_params) == 0

    def test_detect_from_non_json_body(self) -> None:
        ext = TenantExtractor()
        result = ext.extract_from_request(
            query_params={},
            body_str="not json",
            path="/api/data",
        )
        tenant_params = result.get("tenant_parameters", [])
        assert len(tenant_params) == 0

    def test_is_tenant_aware(self) -> None:
        ext = TenantExtractor()
        result = ext.extract_from_request(
            query_params={"instituteId": "abc"},
            body_str=None,
            path="/api/data",
        )
        assert result.get("is_tenant_aware", False) is True

    def test_not_tenant_aware(self) -> None:
        ext = TenantExtractor()
        result = ext.extract_from_request(
            query_params={"page": "1"},
            body_str=None,
            path="/api/data",
        )
        assert result.get("is_tenant_aware", False) is False


# ── Endpoint Classifier Tests ──


class TestEndpointClassifier:
    def test_classify_admin_endpoint(self) -> None:
        classifier = EndpointClassifier()
        result = classifier.classify(method="POST", path="/api/admin/settings")
        assert result["endpoint_type"] is not None
        assert result["sensitivity"] in ("high", "medium", "low")
        assert result["sensitivity"] == "high"

    def test_classify_user_endpoint(self) -> None:
        classifier = EndpointClassifier()
        result = classifier.classify(method="GET", path="/api/users/1")
        assert result is not None
        assert "endpoint_type" in result

    def test_classify_reporting_endpoint(self) -> None:
        classifier = EndpointClassifier()
        result = classifier.classify(method="GET", path="/rptsvc/api/dshbrddtl")
        assert result is not None
        assert result["sensitivity"] in ("high", "medium", "low")

    def test_classify_tenant_endpoint(self) -> None:
        classifier = EndpointClassifier()
        result = classifier.classify(method="PUT", path="/api/institute/config")
        assert result is not None
        assert result.get("tenant_aware") is True or result.get("tenant_aware") is False

    def test_state_changing_increases_risk(self) -> None:
        classifier = EndpointClassifier()
        post_result = classifier.classify(method="POST", path="/api/items")
        get_result = classifier.classify(method="GET", path="/api/items")
        assert post_result["risk_score"] >= get_result["risk_score"]

    def test_classify_health_endpoint(self) -> None:
        classifier = EndpointClassifier()
        result = classifier.classify(method="GET", path="/health")
        assert result["sensitivity"] == "low"

    def test_classify_billing_endpoint(self) -> None:
        classifier = EndpointClassifier()
        result = classifier.classify(method="GET", path="/api/billing/invoices")
        assert result["sensitivity"] in ("high", "medium")

    def test_classify_static_filtered(self) -> None:
        classifier = EndpointClassifier()
        result = classifier.classify(method="GET", path="/assets/logo.png")
        assert result.get("is_static") is True or result["sensitivity"] == "low"

    def test_risk_score_range(self) -> None:
        classifier = EndpointClassifier()
        result = classifier.classify(method="DELETE", path="/api/admin/users")
        assert 0 <= result["risk_score"] <= 100


# ── Role Mapper Tests ──


class TestRoleMapper:
    def test_record_observation(self) -> None:
        mapper = RoleMapper()
        mapper.record_observation(
            role="platform_admin",
            method="GET",
            path="/api/admin/settings",
        )
        summary = mapper.get_summary()
        assert "platform_admin" in summary

    def test_record_observation_no_role(self) -> None:
        mapper = RoleMapper()
        mapper.record_observation(
            role=None,
            method="GET",
            path="/api/public/data",
        )
        # Should not crash
        assert mapper is not None

    def test_infer_hierarchy(self) -> None:
        mapper = RoleMapper()
        mapper.record_observation(role="platform_admin", method="GET", path="/api/admin/settings", permissions=["admin_all"])
        mapper.record_observation(role="institute_admin", method="GET", path="/api/institute/config", permissions=["institute_manage"])
        mapper.record_observation(role="user", method="GET", path="/api/profile", permissions=["view_own"])
        hierarchy = mapper.infer_hierarchy()
        assert len(hierarchy) >= 1

    def test_exclusive_endpoints(self) -> None:
        mapper = RoleMapper()
        mapper.record_observation(role="platform_admin", method="GET", path="/api/admin/settings")
        mapper.record_observation(role="user", method="GET", path="/api/profile")
        exclusives = mapper.get_exclusive_endpoints("platform_admin")
        assert len(exclusives) >= 1

    def test_get_role_tier(self) -> None:
        mapper = RoleMapper()
        mapper.record_observation(
            role="platform_admin",
            method="GET",
            path="/api/admin/settings",
            permissions=["admin_all"],
        )
        tier = mapper.get_role_tier("platform_admin")
        assert tier > 0

    def test_get_stats(self) -> None:
        mapper = RoleMapper()
        mapper.record_observation(role="admin", method="GET", path="/api/admin")
        stats = mapper.get_stats()
        assert isinstance(stats, dict)

    def test_get_summary(self) -> None:
        mapper = RoleMapper()
        mapper.record_observation(role="admin", method="GET", path="/api/admin")
        summary = mapper.get_summary()
        assert isinstance(summary, dict)


# ── AuthzGraph Tests ──


class TestAuthzGraph:
    def test_add_endpoint(self) -> None:
        graph = AuthzGraph()
        graph.add_endpoint(method="GET", path="/api/admin/settings")
        ep = graph.get_endpoint("GET:/api/admin/settings")
        assert ep is not None

    def test_add_role(self) -> None:
        graph = AuthzGraph()
        graph.add_role(role_name="platform_admin", privilege_tier=100)
        roles = graph.get_all_roles()
        assert "platform_admin" in roles

    def test_add_role_endpoint_association(self) -> None:
        graph = AuthzGraph()
        graph.add_endpoint(method="GET", path="/api/admin/settings")
        graph.add_role(role_name="platform_admin", privilege_tier=100)
        graph.add_role_endpoint_association(role_name="platform_admin", method="GET", path="/api/admin/settings")
        endpoints = graph.get_role_endpoints("platform_admin")
        assert len(endpoints) >= 1

    def test_add_tenant_boundary(self) -> None:
        graph = AuthzGraph()
        graph.add_tenant_boundary(
            param_name="instituteId",
            param_value="64e85a...",
            tenant_type="institute",
            endpoint_key="GET:/api/data",
        )
        boundaries = graph.get_tenant_boundaries()
        assert len(boundaries) >= 1

    def test_add_authz_signal(self) -> None:
        graph = AuthzGraph()
        graph.add_authz_signal(
            signal_type="potential_vertical_escalation",
            endpoint_key="GET:/api/admin/settings",
            role="user",
            details={"privilege_tier": 10},
        )
        signals = graph.get_authz_signals()
        assert len(signals) >= 1

    def test_get_high_risk_endpoints(self) -> None:
        graph = AuthzGraph()
        graph.add_endpoint(method="DELETE", path="/api/admin/users", sensitivity="high", risk_score=80)
        high_risk = graph.get_high_risk_endpoints()
        assert len(high_risk) >= 1

    def test_get_testing_targets(self) -> None:
        graph = AuthzGraph()
        graph.add_endpoint(method="POST", path="/api/admin/settings", sensitivity="high", risk_score=80)
        targets = graph.get_testing_targets()
        assert isinstance(targets, list)

    def test_to_dict_export(self) -> None:
        graph = AuthzGraph()
        graph.add_endpoint(method="GET", path="/api/data")
        data = graph.to_dict()
        assert isinstance(data, dict)
        assert "endpoints" in data

    def test_save_and_load(self) -> None:
        graph = AuthzGraph()
        graph.add_endpoint(method="GET", path="/api/data")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            graph.save(filepath)
            loaded = AuthzGraph.load(filepath)
            assert loaded is not None
            ep = loaded.get_endpoint("GET:/api/data")
            assert ep is not None
        finally:
            os.unlink(filepath)

    def test_get_summary(self) -> None:
        graph = AuthzGraph()
        graph.add_endpoint(method="GET", path="/api/data")
        summary = graph.get_summary()
        assert isinstance(summary, dict)

    def test_capability_association(self) -> None:
        graph = AuthzGraph()
        graph.add_endpoint(method="GET", path="/api/data")
        graph.add_capability_association(capability="manage_institutes", endpoint_key="GET:/api/data")
        data = graph.to_dict()
        assert isinstance(data, dict)


# ── Integration Tests ──


class TestAuthIntegration:
    def test_jwt_to_capability_pipeline(self) -> None:
        """Test that JWT claims flow through to capabilities."""
        payload = {
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Platform Admin",
            "prms": [
                "PRM_1_PortalInstitute_Create",
                "PRM_1_PortalInstitute_Modify",
                "PRM_1_SystemUser_Create",
            ],
            "nameidentifier": "663c79ef001f1f13fa5dbba4",
            "RoleId": "62d657368570ac2e66028c2e",
        }
        token = _make_jwt(payload)
        headers = _make_bearer_header(token)

        # Decode JWT
        decoder = JWTDecoder()
        jwt_result = decoder.decode_from_headers(headers)
        assert jwt_result is not None

        # Build identity context
        context = decoder.build_identity_context(jwt_result)
        assert context is not None
        assert context["role"] == "platform_admin"

        # Map capabilities
        mapper = CapabilityMapper()
        capabilities = mapper.map_permissions(context.get("permissions", []))
        assert len(capabilities) > 0
        assert "manage_institutes" in capabilities

    def test_tenant_aware_endpoint_classification(self) -> None:
        """Test that tenant parameters are detected and endpoints classified."""
        ext = TenantExtractor()
        query_params = {"instituteId": "64e85a...", "page": "1"}
        result = ext.extract_from_request(query_params=query_params, body_str=None, path="/api/data")
        tenant_params = result.get("tenant_parameters", [])
        assert len(tenant_params) >= 1

        classifier = EndpointClassifier()
        classification = classifier.classify(method="GET", path="/api/institute/config")
        assert classification is not None

    def test_role_mapper_to_authz_graph(self) -> None:
        """Test role mapper feeds into authz graph."""
        mapper = RoleMapper()
        mapper.record_observation(role="platform_admin", method="GET", path="/api/admin/settings", permissions=["admin_all"])
        mapper.record_observation(role="user", method="GET", path="/api/profile", permissions=["view_own"])

        hierarchy = mapper.infer_hierarchy()
        assert len(hierarchy) >= 1

    def test_full_classification_pipeline(self) -> None:
        """Test the full classification pipeline for a realistic endpoint."""
        classifier = EndpointClassifier()
        classification = classifier.classify(method="POST", path="/rptsvc/api/dshbrddtl")
        assert classification is not None
        assert "sensitivity" in classification
        assert "risk_score" in classification

        ext = TenantExtractor()
        tenant_result = ext.extract_from_request(
            query_params={"instituteId": "64e85a..."},
            body_str=None,
            path="/rptsvc/api/dshbrddtl",
        )
        assert tenant_result.get("is_tenant_aware") is True