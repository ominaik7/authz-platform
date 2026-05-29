"""Burp Suite XML parser — loads and decodes Burp XML export files."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from lxml import etree

from ..utils.encoding import decode_base64

logger = logging.getLogger(__name__)


@dataclass
class RawTrafficItem:
    """A single raw request/response pair extracted from Burp XML."""

    raw_request: str
    raw_response: str
    url: str
    status: int = 0
    mimetype: str = ""
    host: str = ""
    port: int = 0
    protocol: str = "http"
    method: str = ""
    path: str = ""
    time: str = ""
    comment: str = ""
    decode_errors: list[str] = field(default_factory=list)


def parse_burp_xml(file_path: str) -> list[RawTrafficItem]:
    """Parse a Burp Suite XML export and return raw traffic items.

    Handles:
    - CDATA-wrapped content
    - Base64-encoded request/response (base64="true" attribute)
    - Malformed XML gracefully

    Args:
        file_path: Path to the Burp XML file.

    Returns:
        List of RawTrafficItem objects with decoded request/response data.
    """
    items: list[RawTrafficItem] = []

    try:
        tree = etree.parse(file_path)
    except etree.XMLSyntaxError as exc:
        logger.error(
            "Failed to parse XML: %s",
            exc,
            extra={"parser_stage": "xml_parse"},
        )
        return items

    root = tree.getroot()

    for idx, item_elem in enumerate(root.iter("item")):
        item = _parse_item(item_elem, idx)
        if item is not None:
            items.append(item)

    logger.info(
        "Parsed %d items from Burp XML",
        len(items),
        extra={"parser_stage": "burp_xml_parse"},
    )
    return items


def _parse_item(item_elem: etree._Element, idx: int) -> Optional[RawTrafficItem]:
    """Parse a single <item> element from Burp XML."""
    decode_errors: list[str] = []

    # Extract simple text fields
    url = _text(item_elem, "url")
    host = _text(item_elem, "host")
    port_str = _text(item_elem, "port")
    protocol = _text(item_elem, "protocol") or "http"
    method = _text(item_elem, "method")
    path = _text(item_elem, "path")
    time_str = _text(item_elem, "time")
    comment = _text(item_elem, "comment")
    mimetype = _text(item_elem, "mimetype")

    try:
        status = int(_text(item_elem, "status") or "0")
    except ValueError:
        status = 0

    try:
        port = int(port_str or "0")
    except ValueError:
        port = 0

    # Decode request
    request_elem = item_elem.find("request")
    raw_request = _decode_element(request_elem, "request", idx, decode_errors)

    # Decode response
    response_elem = item_elem.find("response")
    raw_response = _decode_element(response_elem, "response", idx, decode_errors)

    if raw_request is None and raw_response is None:
        logger.warning(
            "Item %d: both request and response are empty, skipping",
            idx,
            extra={"request_id": f"raw_{idx:03d}", "parser_stage": "burp_xml_parse"},
        )
        return None

    return RawTrafficItem(
        raw_request=raw_request or "",
        raw_response=raw_response or "",
        url=url or "",
        status=status,
        mimetype=mimetype,
        host=host,
        port=port,
        protocol=protocol,
        method=method,
        path=path or "",
        time=time_str,
        comment=comment,
        decode_errors=decode_errors,
    )


def _text(elem: etree._Element, tag: str) -> Optional[str]:
    """Extract text content of a child element, safely."""
    child = elem.find(tag)
    if child is None:
        return None
    return (child.text or "").strip() if child.text else None


def _decode_element(
    elem: Optional[etree._Element],
    label: str,
    idx: int,
    decode_errors: list[str],
) -> Optional[str]:
    """Decode an element that may be base64-encoded.

    Checks the base64="true" attribute. If present, decodes.
    Otherwise returns the raw text.
    """
    if elem is None:
        return None

    is_b64 = elem.get("base64", "false").lower() == "true"
    raw_text = elem.text or ""

    if not raw_text.strip():
        return ""

    if is_b64:
        decoded = decode_base64(raw_text)
        if decoded is None:
            err_msg = f"Item {idx}: failed to decode base64 {label}"
            decode_errors.append(err_msg)
            logger.warning(
                err_msg,
                extra={
                    "request_id": f"raw_{idx:03d}",
                    "parser_stage": "base64_decode",
                    "decode_errors": err_msg,
                },
            )
            return raw_text  # fallback: return raw text
        return decoded

    return raw_text