from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any
import json

TOP_LEVEL_FIELDS = (
    "event_id", "timestamp", "event_type", "source", "host", "user",
    "process", "command_line", "source_ip", "destination_ip", "source_port",
    "destination_port", "file_path", "file_hash", "artifact", "action", "metadata"
)

@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: str | None
    event_type: str
    source: str | None
    host: str | None
    user: str | None
    process: str | None
    command_line: str | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    file_path: str | None
    file_hash: str | None
    artifact: str | None
    action: str | None
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Keep the exact top-level contract and no extras.
        return {field: data[field] for field in TOP_LEVEL_FIELDS}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def validate_dict(cls, payload: dict[str, Any]) -> None:
        extra = set(payload) - set(TOP_LEVEL_FIELDS)
        missing = set(TOP_LEVEL_FIELDS) - set(payload)
        if extra:
            raise ValueError(f"Unexpected top-level fields: {sorted(extra)}")
        if missing:
            raise ValueError(f"Missing top-level fields: {sorted(missing)}")
        if not isinstance(payload.get("metadata"), dict):
            raise ValueError("metadata must be an object")
