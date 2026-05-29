
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ReplayRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: str | None = None
    cookies: dict[str, str] | None = None

@dataclass
class ReplayResult:
    status_code: int
    headers: dict[str, str]
    body: str
    duration_ms: int

@dataclass
class ReplayFinding:
    finding_type: str
    severity: str
    description: str
    original_role: str
    replay_role: str
    endpoint: str
    evidence: dict[str, Any] = field(default_factory=dict)
