from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.constants import (
    EVIDENCE_TYPE_DISK_IMAGE,
    EVIDENCE_TYPE_MEMORY_DUMP,
    EVIDENCE_TYPE_NETWORK_CAPTURE,
    EVIDENCE_TYPE_WINDOWS_EVENT_LOG,
    EVIDENCE_TYPE_WINDOWS_REGISTRY,
    EVIDENCE_TYPE_STRUCTURED_EXPORT,
    EVIDENCE_TYPE_INDIVIDUAL_ARTIFACT,
    EVIDENCE_TYPE_AMBIGUOUS,
    EVIDENCE_TYPE_UNKNOWN,
)
from app.evidence_identifier import ClassificationResult, identify_evidence


@dataclass(frozen=True)
class InputRoute:
    kind: str
    primary_tools: tuple[str, ...]
    description: str
    reason: str
    classification: ClassificationResult | None = None


def classify_input(path: str | Path, requested_kind: str = "auto") -> InputRoute:
    """Classifies the evidence using reliable forensic indicators and maps to forensic tools."""
    p = Path(path)
    res = identify_evidence(p, requested_kind=requested_kind)

    if res.detected_type == EVIDENCE_TYPE_DISK_IMAGE:
        return InputRoute(
            kind="disk",
            primary_tools=("Autopsy", "Plaso"),
            description="Disk/filesystem forensic evidence + timeline extraction",
            reason=f"Detected {res.detected_format} (confidence: {res.confidence:.2f})",
            classification=res,
        )

    if res.detected_type == EVIDENCE_TYPE_MEMORY_DUMP:
        return InputRoute(
            kind="memory",
            primary_tools=("Volatility 3",),
            description="Memory forensic analysis",
            reason=f"Detected {res.detected_format} (confidence: {res.confidence:.2f})",
            classification=res,
        )

    if res.detected_type == EVIDENCE_TYPE_NETWORK_CAPTURE:
        return InputRoute(
            kind="packet",
            primary_tools=("Plaso",),
            description="Packet/timestamp-oriented evidence; Plaso attempted for supported parsers",
            reason=f"Detected {res.detected_format} (confidence: {res.confidence:.2f})",
            classification=res,
        )

    if res.detected_type == EVIDENCE_TYPE_STRUCTURED_EXPORT:
        return InputRoute(
            kind="timeline",
            primary_tools=(),
            description="Already-structured event data; normalize directly",
            reason=f"Detected {res.detected_format} (confidence: {res.confidence:.2f})",
            classification=res,
        )

    if res.detected_type in (
        EVIDENCE_TYPE_WINDOWS_EVENT_LOG,
        EVIDENCE_TYPE_WINDOWS_REGISTRY,
        EVIDENCE_TYPE_INDIVIDUAL_ARTIFACT,
    ):
        return InputRoute(
            kind="timeline",
            primary_tools=("Plaso",),
            description="Timeline/artifact extraction via Plaso",
            reason=f"Detected {res.detected_format} (confidence: {res.confidence:.2f})",
            classification=res,
        )

    if res.detected_type == EVIDENCE_TYPE_AMBIGUOUS:
        raise ValueError(
            f"Ambiguous evidence '{p.name}': {res.metadata.get('reason', 'Could not distinguish disk from memory')}. "
            "Please specify explicit target kind using --kind disk or --kind memory."
        )

    raise ValueError(
        f"Unsupported or unknown evidence format for '{p.name}'. "
        "Classification marked as unrecognized. Specify explicit --kind to force processing."
    )
