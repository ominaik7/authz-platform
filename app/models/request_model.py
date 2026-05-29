"""Pydantic models for HTTP request data — Phase 1.5: Authorization Intelligence."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ResourceID(BaseModel):
    """A resource identifier extracted from a URL path or body."""

    type: str = Field(..., description="Type of ID: numeric, uuid, mongo_id")
    value: str = Field(..., description="The extracted ID value")


class RequestModel(BaseModel):
    """Normalized HTTP request model — identity-centric design for authorization intelligence."""

    id: str = Field(..., description="Unique request identifier, e.g. req_001")
    method: str = Field(..., description="HTTP method: GET, POST, PUT, PATCH, DELETE")
    url: str = Field(..., description="Full reconstructed URL")
    path: str = Field(..., description="URL path component")
    headers: dict[str, str] = Field(
        default_factory=dict, description="Request headers as key-value pairs"
    )
    query_params: dict[str, str] = Field(
        default_factory=dict, description="Query string parameters"
    )
    cookies: dict[str, str] = Field(
        default_factory=dict, description="Parsed cookies from Cookie header"
    )
    body: str | None = Field(default=None, description="Request body as string")

    # ── Phase 1.5: Authorization Intelligence Fields ──
    identity_context: dict[str, Any] | None = Field(
        default=None,
        description="WHO made the request: role, privilege_tier, permissions, tenant_scope",
    )
    authorization_context: dict[str, Any] | None = Field(
        default=None,
        description="WHAT authorization boundaries apply: tenant_parameter, capabilities",
    )
    endpoint_metadata: dict[str, Any] | None = Field(
        default=None,
        description="WHICH endpoint characteristics: sensitivity, admin_only, tenant_aware",
    )


class ResponseModel(BaseModel):
    """Normalized HTTP response model — enhanced with structured body parsing."""

    status_code: int = Field(..., description="HTTP status code")
    headers: dict[str, str] = Field(
        default_factory=dict, description="Response headers as key-value pairs"
    )
    body: str | None = Field(default=None, description="Response body as string")
    content_type: str | None = Field(
        default=None, description="Normalized content type (e.g. application/json)"
    )

    # ── Phase 1.5: Structured Response Intelligence ──
    parsed_json: dict[str, Any] | list[Any] | None = Field(
        default=None, description="Parsed JSON body if content-type is JSON"
    )
    body_hash: str | None = Field(
        default=None, description="SHA256 hash of response body for dedup/change detection"
    )
    body_size: int = Field(
        default=0, description="Size of response body in bytes"
    )
    body_preview: str | None = Field(
        default=None, description="Truncated preview of response body (first 500 chars)"
    )


class HTTPTransaction(BaseModel):
    """A combined request-response transaction with metadata — replay-ready architecture."""

    request: RequestModel
    response: ResponseModel
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Extra metadata: resource_ids, api_candidate, fingerprint, etc.",
    )
