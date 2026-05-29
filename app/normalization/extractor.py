"""Resource ID extractor — extracts numeric, UUID, and Mongo IDs from URLs and bodies."""

import json
import re
from dataclasses import dataclass


@dataclass
class ResourceIdentifier:
    type: str
    value: str
    location: str


UUID_REGEX = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)

MONGO_REGEX = re.compile(
    r"\b[a-f0-9]{24}\b",
    re.IGNORECASE,
)

NUMERIC_REGEX = re.compile(
    r"/(\d+)(?:/|$)"
)


BODY_ID_REGEX = re.compile(
    r'"(?:id|userId|ownerId|accountId)"\s*:\s*(\d+)',
    re.IGNORECASE,
)


def extract_resource_ids(
    path: str,
    body: str | None = None,
) -> list[ResourceIdentifier]:
    """
    Extract resource identifiers from:
    - URL path
    - JSON body

    Returns:
        list[ResourceIdentifier]
    """

    results: list[ResourceIdentifier] = []
    seen: set[tuple[str, str]] = set()

    def add_id(id_type: str, value: str, location: str) -> None:
        key = (id_type, value)

        if key in seen:
            return

        seen.add(key)

        results.append(
            ResourceIdentifier(
                type=id_type,
                value=value,
                location=location,
            )
        )

    # UUIDs
    for match in UUID_REGEX.findall(path):
        add_id("uuid", match, "path")

    # Mongo IDs
    for match in MONGO_REGEX.findall(path):
        add_id("mongo_id", match, "path")

    # Numeric IDs
    for match in NUMERIC_REGEX.findall(path):
        add_id("numeric", match, "path")

    # Body extraction
    if body:

        # JSON body parsing
        try:
            parsed = json.loads(body)

            if isinstance(parsed, dict):

                for key, value in parsed.items():

                    key_lower = key.lower()

                    if key_lower.endswith("id"):

                        if isinstance(value, int):
                            add_id(
                                "numeric",
                                str(value),
                                "body",
                            )

                        elif isinstance(value, str):

                            if UUID_REGEX.fullmatch(value):
                                add_id(
                                    "uuid",
                                    value,
                                    "body",
                                )

                            elif MONGO_REGEX.fullmatch(value):
                                add_id(
                                    "mongo_id",
                                    value,
                                    "body",
                                )

        except Exception:
            pass

        # Regex fallback
        for match in BODY_ID_REGEX.findall(body):
            add_id("numeric", match, "body")

    return results
