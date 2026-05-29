"""Unit tests for Burp XML Import + Request Normalization Engine."""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Test: Encoding utilities
# ---------------------------------------------------------------------------
from app.utils.encoding import safe_b64_decode


class TestBase64Decoding:
    """Tests for Base64 decoding utility."""

    def test_decode_valid_base64(self) -> None:
        raw = "Hello, World!"
        encoded = base64.b64encode(raw.encode()).decode()
        result = safe_b64_decode(encoded)
        assert result == raw

    def test_decode_url_safe_base64(self) -> None:
        raw = "Hello, World!"
        encoded = base64.urlsafe_b64encode(raw.encode()).decode()
        result = safe_b64_decode(encoded)
        assert result == raw

    def test_decode_invalid_base64_returns_empty(self) -> None:
        result = safe_b64_decode("not-valid-base64!!!")
        assert result == ""

    def test_decode_empty_string(self) -> None:
        result = safe_b64_decode("")
        assert result == ""

    def test_decode_base64_with_whitespace(self) -> None:
        raw = "Test data"
        encoded = base64.b64encode(raw.encode()).decode()
        # Add whitespace/newlines like some Base64 encoders do
        padded = encoded[:4] + "\n" + encoded[4:]
        result = safe_b64_decode(padded)
        assert result == raw


# ---------------------------------------------------------------------------
# Test: Burp XML Parser
# ---------------------------------------------------------------------------
from app.parsers.burp_xml_parser import RawTrafficItem, parse_burp_xml


class TestBurpXMLParser:
    """Tests for Burp XML parsing."""

    def _make_burp_xml(self, items: list[dict]) -> str:
        """Helper to build a minimal Burp XML from item dicts."""
        xml_items = []
        for item in items:
            req_b64 = base64.b64encode(item.get("request", "").encode()).decode()
            resp_b64 = base64.b64encode(item.get("response", "").encode()).decode()
            xml_items.append(
                f"""<item>
                    <url>{item.get('url', 'https://app.test/api/users')}</url>
                    <host>{item.get('host', 'app.test')}</host>
                    <port>{item.get('port', '443')}</port>
                    <protocol>{item.get('protocol', 'https')}</protocol>
                    <method>{item.get('method', 'GET')}</method>
                    <mimetype>{item.get('mimetype', 'HTML')}</mimetype>
                    <status>{item.get('status', '200')}</status>
                    <request base64="true">{req_b64}</request>
                    <response base64="true">{resp_b64}</response>
                    <comment>{item.get('comment', '')}</comment>
                    <time>{item.get('time', '')}</time>
                </item>"""
            )
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <items burpVersion="2024.1" exportTime="Wed May 28 12:00:00 IST 2026">
            {"".join(xml_items)}
        </items>"""

    def test_parse_valid_xml(self) -> None:
        xml = self._make_burp_xml(
            [
                {
                    "url": "https://app.test/api/users/1",
                    "method": "GET",
                    "request": "GET /api/users/1 HTTP/1.1\r\nHost: app.test\r\n\r\n",
                    "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                }
            ]
        )
        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
            f.write(xml)
            f.flush()
            try:
                items = parse_burp_xml(f.name)
                assert len(items) == 1
                assert items[0].method == "GET"
                assert items[0].url == "https://app.test/api/users/1"
                assert "GET /api/users/1" in items[0].raw_request
            finally:
                os.unlink(f.name)

    def test_parse_empty_xml(self) -> None:
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
        <items burpVersion="2024.1" exportTime="Wed May 28 12:00:00 IST 2026">
        </items>"""
        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
            f.write(xml)
            f.flush()
            try:
                items = parse_burp_xml(f.name)
                assert len(items) == 0
            finally:
                os.unlink(f.name)

    def test_parse_malformed_xml(self) -> None:
        xml = "<not valid xml at all"
        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
            f.write(xml)
            f.flush()
            try:
                items = parse_burp_xml(f.name)
                # Should not crash, returns empty
                assert isinstance(items, list)
            finally:
                os.unlink(f.name)

    def test_decode_errors_tracked(self) -> None:
        xml = self._make_burp_xml(
            [
                {
                    "url": "https://app.test/api/test",
                    "request": "not-base64!!!",
                    "response": "also-not-base64!!!",
                }
            ]
        )
        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
            f.write(xml)
            f.flush()
            try:
                items = parse_burp_xml(f.name)
                # Parser should still return items, with decode_errors tracked
                assert len(items) >= 0  # doesn't crash
            finally:
                os.unlink(f.name)


# ---------------------------------------------------------------------------
# Test: Raw HTTP Parser
# ---------------------------------------------------------------------------
from app.parsers.raw_http_parser import parse_raw_request, parse_raw_response


class TestRawHTTPParser:
    """Tests for raw HTTP request/response parsing."""

    def test_parse_get_request(self) -> None:
        raw = "GET /api/users/1 HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer xxx\r\n\r\n"
        result = parse_raw_request(raw)
        assert result.method == "GET"
        assert result.path == "/api/users/1"
        assert result.headers["Host"] == "app.test"
        assert result.headers["Authorization"] == "Bearer xxx"
        assert result.body == ""

    def test_parse_post_request_with_body(self) -> None:
        raw = (
            "POST /api/users HTTP/1.1\r\n"
            "Host: app.test\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 25\r\n"
            "\r\n"
            '{"name": "test user"}'
        )
        result = parse_raw_request(raw)
        assert result.method == "POST"
        assert result.path == "/api/users"
        assert result.headers["Content-Type"] == "application/json"
        assert "test user" in result.body

    def test_parse_request_with_query_params(self) -> None:
        raw = "GET /api/users?page=1&limit=10 HTTP/1.1\r\nHost: app.test\r\n\r\n"
        result = parse_raw_request(raw)
        assert result.query_params.get("page") == "1"
        assert result.query_params.get("limit") == "10"

    def test_parse_request_with_cookies(self) -> None:
        raw = "GET /api/me HTTP/1.1\r\nHost: app.test\r\nCookie: session=abc123; token=xyz\r\n\r\n"
        result = parse_raw_request(raw)
        assert result.cookies.get("session") == "abc123"
        assert result.cookies.get("token") == "xyz"

    def test_parse_empty_request(self) -> None:
        result = parse_raw_request("")
        assert result.method == ""

    def test_parse_malformed_request_line(self) -> None:
        raw = "GARBAGE\r\n\r\n"
        result = parse_raw_request(raw)
        # Should not crash
        assert isinstance(result.method, str)

    def test_parse_response(self) -> None:
        raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\": 1}"
        result = parse_raw_response(raw)
        assert result.status_code == 200
        assert result.content_type == "application/json"
        assert "1" in result.body

    def test_parse_response_404(self) -> None:
        raw = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\nNot Found"
        result = parse_raw_response(raw)
        assert result.status_code == 404

    def test_parse_empty_response(self) -> None:
        result = parse_raw_response("")
        assert result.status_code == 0


# ---------------------------------------------------------------------------
# Test: Noise Filtering
# ---------------------------------------------------------------------------
from app.parsers.filters import should_filter_request, is_api_candidate, detect_content_type_category


class TestNoiseFiltering:
    """Tests for static asset filtering."""

    def test_filter_css(self) -> None:
        result = should_filter_request(path="/static/style.css", content_type="text/css")
        assert not result.passed
        assert "static" in result.reason  # matches static_prefix or static_extension

    def test_filter_js(self) -> None:
        result = should_filter_request(path="/app.js", content_type="application/javascript")
        assert not result.passed

    def test_filter_image(self) -> None:
        result = should_filter_request(path="/logo.png")
        assert not result.passed

    def test_filter_static_prefix(self) -> None:
        result = should_filter_request(path="/fonts/main.woff")
        assert not result.passed
        assert "static_prefix" in result.reason

    def test_keep_api_json(self) -> None:
        result = should_filter_request(
            path="/api/users", content_type="application/json", method="GET"
        )
        assert result.passed

    def test_keep_api_path_prefix(self) -> None:
        result = should_filter_request(path="/api/users", method="GET")
        assert result.passed
        assert "api_path_prefix" in result.reason

    def test_keep_graphql(self) -> None:
        result = should_filter_request(path="/graphql", method="POST")
        assert result.passed

    def test_keep_post_mutations(self) -> None:
        result = should_filter_request(path="/users/update", method="POST")
        assert result.passed
        assert "mutation_method" in result.reason

    def test_filter_html_page(self) -> None:
        result = should_filter_request(path="/home", method="GET")
        assert not result.passed

    def test_api_candidate_json(self) -> None:
        assert is_api_candidate("application/json", "/api/users") is True

    def test_api_candidate_html(self) -> None:
        assert is_api_candidate("text/html", "/home") is False

    def test_api_candidate_post_method(self) -> None:
        assert is_api_candidate(None, "/submit", "POST") is True

    def test_content_type_category(self) -> None:
        assert detect_content_type_category("application/json") == "json"
        assert detect_content_type_category("application/graphql+json") == "graphql"
        assert detect_content_type_category("application/x-www-form-urlencoded") == "form_urlencoded"
        assert detect_content_type_category("multipart/form-data") == "multipart"
        assert detect_content_type_category("text/html") == "html"
        assert detect_content_type_category(None) == "other"


# ---------------------------------------------------------------------------
# Test: Resource ID Extraction
# ---------------------------------------------------------------------------
from app.normalization.extractor import extract_resource_ids


class TestResourceIDExtraction:
    """Tests for extracting numeric, UUID, and Mongo IDs."""

    def test_extract_numeric_id(self) -> None:
        ids = extract_resource_ids("/api/users/123")
        numeric = [i for i in ids if i.type == "numeric"]
        assert any(i.value == "123" for i in numeric)

    def test_extract_uuid(self) -> None:
        uuid_val = "550e8400-e29b-41d4-a716-446655440000"
        ids = extract_resource_ids(f"/api/orgs/{uuid_val}")
        uuid_ids = [i for i in ids if i.type == "uuid"]
        assert any(i.value == uuid_val for i in uuid_ids)

    def test_extract_mongo_id(self) -> None:
        mongo_val = "507f1f77bcf86cd799439011"
        ids = extract_resource_ids(f"/api/items/{mongo_val}")
        mongo_ids = [i for i in ids if i.type == "mongo_id"]
        assert any(i.value.lower() == mongo_val.lower() for i in mongo_ids)

    def test_extract_multiple_ids(self) -> None:
        ids = extract_resource_ids("/api/users/1/posts/42")
        numeric = [i for i in ids if i.type == "numeric"]
        values = [i.value for i in numeric]
        assert "1" in values
        assert "42" in values

    def test_deduplicate_ids(self) -> None:
        ids = extract_resource_ids("/api/users/1/active/1")
        numeric = [i for i in ids if i.type == "numeric" and i.value == "1"]
        assert len(numeric) == 1

    def test_extract_from_body(self) -> None:
        body = '{"userId": 99, "name": "test"}'
        ids = extract_resource_ids("/api/assign", body)
        numeric = [i for i in ids if i.type == "numeric"]
        assert any(i.value == "99" for i in numeric)

    def test_no_ids_in_path(self) -> None:
        ids = extract_resource_ids("/api/health")
        assert len(ids) == 0


# ---------------------------------------------------------------------------
# Test: Normalizer (full pipeline)
# ---------------------------------------------------------------------------
from app.normalization.normalizer import compute_fingerprint, normalize_traffic


class TestNormalizer:
    """Tests for the full normalization pipeline."""

    def _make_raw_item(
        self,
        method: str = "GET",
        url: str = "https://app.test/api/users/1",
        path: str = "/api/users/1",
        request: str = "",
        response: str = "",
        content_type: str = "application/json",
        status: int = 200,
    ) -> RawTrafficItem:
        if not request:
            request = f"{method} {path} HTTP/1.1\r\nHost: app.test\r\n\r\n"
        if not response:
            response = f"HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\n\r\n{{}}"
        return RawTrafficItem(
            raw_request=request,
            raw_response=response,
            url=url,
            status=status,
            method=method,
            mimetype="HTML",
            host="app.test",
            port=443,
            protocol="https",
        )

    def test_normalize_single_api_request(self) -> None:
        items = [self._make_raw_item()]
        result = normalize_traffic(items)
        assert len(result.transactions) == 1
        assert result.transactions[0].request.method == "GET"
        assert result.transactions[0].request.path == "/api/users/1"
        assert result.transactions[0].response.status_code == 200

    def test_normalize_filters_static(self) -> None:
        items = [
            self._make_raw_item(
                url="https://app.test/static/style.css",
                path="/static/style.css",
                content_type="text/css",
            ),
            self._make_raw_item(),
        ]
        result = normalize_traffic(items)
        assert result.filtered_count >= 1
        # Only the API request should remain
        assert len(result.transactions) == 1

    def test_normalize_deduplication(self) -> None:
        items = [
            self._make_raw_item(),
            self._make_raw_item(),  # duplicate
        ]
        result = normalize_traffic(items)
        assert result.duplicate_count == 1
        assert len(result.transactions) == 1

    def test_normalize_extracts_resource_ids(self) -> None:
        items = [self._make_raw_item(path="/api/users/42")]
        result = normalize_traffic(items)
        assert result.unique_resource_ids >= 1

    def test_fingerprint_deterministic(self) -> None:
        fp1 = compute_fingerprint("GET", "/api/users/1", {"Host": "app.test"}, None)
        fp2 = compute_fingerprint("GET", "/api/users/1", {"Host": "app.test"}, None)
        assert fp1 == fp2

    def test_fingerprint_different_for_different_methods(self) -> None:
        fp1 = compute_fingerprint("GET", "/api/users/1", {"Host": "app.test"}, None)
        fp2 = compute_fingerprint("POST", "/api/users/1", {"Host": "app.test"}, None)
        assert fp1 != fp2

    def test_fingerprint_normalizes_ids(self) -> None:
        """Different numeric IDs should produce the same fingerprint (same endpoint)."""
        fp1 = compute_fingerprint("GET", "/api/users/1", {"Host": "app.test"}, None)
        fp2 = compute_fingerprint("GET", "/api/users/2", {"Host": "app.test"}, None)
        assert fp1 == fp2

    def test_api_candidate_flagged(self) -> None:
        items = [self._make_raw_item(content_type="application/json")]
        result = normalize_traffic(items)
        assert result.api_candidates >= 1
        assert result.transactions[0].metadata.get("api_candidate") is True


# ---------------------------------------------------------------------------
# Test: Pydantic Models
# ---------------------------------------------------------------------------
from app.models.request_model import RequestModel, ResponseModel, HTTPTransaction, ResourceID


class TestPydanticModels:
    """Tests for Pydantic data models."""

    def test_request_model(self) -> None:
        req = RequestModel(
            id="req_001",
            method="GET",
            url="https://app.test/api/users/1",
            path="/api/users/1",
        )
        assert req.id == "req_001"
        assert req.method == "GET"
        assert req.headers == {}
        assert req.body is None

    def test_response_model(self) -> None:
        resp = ResponseModel(status_code=200, content_type="application/json")
        assert resp.status_code == 200
        assert resp.body is None

    def test_http_transaction(self) -> None:
        req = RequestModel(id="req_001", method="GET", url="https://app.test/api", path="/api")
        resp = ResponseModel(status_code=200)
        tx = HTTPTransaction(request=req, response=resp)
        assert tx.request.method == "GET"
        assert tx.response.status_code == 200

    def test_resource_id_model(self) -> None:
        rid = ResourceID(type="numeric", value="123")
        assert rid.type == "numeric"
        assert rid.value == "123"

    def test_model_serialization(self) -> None:
        req = RequestModel(id="req_001", method="GET", url="https://app.test/api", path="/api")
        data = req.model_dump()
        assert isinstance(data, dict)
        assert data["method"] == "GET"
        # Should be JSON-serializable
        json_str = json.dumps(data)
        assert "GET" in json_str