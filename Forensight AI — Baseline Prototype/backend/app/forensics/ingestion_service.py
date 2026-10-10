"""
Forensight AI - M3 Ingestion Service (Module 3)
Receives normalized M1 forensic payloads, validates contracts, verifies cryptographic hashes,
persists artifacts and events with full provenance and duplicate protection in SQLite transactions.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.models import Evidence, Artifact, Event, AuditLog
from app.forensics.event_semantics import map_canonical_event_type

logger = logging.getLogger("forensight.ingestion")

M1_TOP_LEVEL_FIELDS = (
    "event_id", "timestamp", "event_type", "source", "host", "user",
    "process", "command_line", "source_ip", "destination_ip", "source_port",
    "destination_port", "file_path", "file_hash", "artifact", "action", "metadata"
)


class IngestionError(Exception):
    """Raised when an M1->M3 ingestion contract or verification fails."""
    pass


def validate_m1_event_contract(raw_event: Dict[str, Any], index: int = 0) -> None:
    """
    Validates that a single event adheres to the strict 17-field common schema contract.
    """
    if not isinstance(raw_event, dict):
        raise IngestionError(f"Event at index {index} is not a valid JSON dictionary")

    # Check for missing required top-level fields
    missing = [field for field in M1_TOP_LEVEL_FIELDS if field not in raw_event]
    if missing:
        raise IngestionError(f"Event at index {index} is missing required fields: {missing}")

    if not raw_event.get("event_id"):
        raise IngestionError(f"Event at index {index} is missing required 'event_id'")

    if not raw_event.get("event_type"):
        raise IngestionError(f"Event at index {index} is missing required 'event_type'")

    if raw_event.get("metadata") is not None and not isinstance(raw_event.get("metadata"), dict):
        raise IngestionError(f"Event at index {index} 'metadata' must be a JSON dictionary or null")


def validate_m1_payload(payload: Dict[str, Any]) -> None:
    """
    Validates the versioned M1->M3 ingestion payload structure.
    """
    if not isinstance(payload, dict):
        raise IngestionError("Ingestion payload must be a JSON dictionary")

    events = payload.get("events")
    if not isinstance(events, list):
        raise IngestionError("Ingestion payload must contain an 'events' list")

    for i, ev in enumerate(events):
        validate_m1_event_contract(ev, index=i)


def parse_event_timestamp(raw_timestamp: Any) -> Optional[datetime]:
    """
    Safely parses an event timestamp string into a timezone-naive UTC datetime.
    Forensic events may legitimately lack timestamps; returns None if missing or invalid.
    NEVER invents a timestamp.
    """
    if not raw_timestamp:
        return None

    if isinstance(raw_timestamp, datetime):
        return raw_timestamp.replace(tzinfo=None)

    if isinstance(raw_timestamp, str):
        cleaned = raw_timestamp.strip()
        if not cleaned or cleaned.lower() in ("null", "none", "n/a", "--:--:--", "0000-00-00"):
            return None

        # Replace trailing Z with UTC offset
        cleaned = cleaned.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(cleaned)
            return dt.replace(tzinfo=None)
        except ValueError:
            pass

        # Try common forensic formats
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
        ):
            try:
                return datetime.strptime(cleaned, fmt)
            except ValueError:
                continue

    return None


def get_or_create_artifact(
    db: Session,
    evidence: Evidence,
    artifact_name: Optional[str],
    source_name: Optional[str],
    parser_info: str = "M1 Forensic Normalizer",
    raw_info: Optional[Dict[str, Any]] = None,
) -> Artifact:
    """
    Finds or creates an Artifact record for the specified evidence and tool/source.
    Ensures artifacts are reused rather than creating duplicates.
    """
    resolved_type = "LOG"
    src_lower = (source_name or artifact_name or "").lower()
    if "registry" in src_lower or "reg" in src_lower or ".dat" in src_lower:
        resolved_type = "REGISTRY"
    elif "process" in src_lower or "volatility" in src_lower:
        resolved_type = "PROCESS"
    elif "network" in src_lower or "pcap" in src_lower or "flow" in src_lower:
        resolved_type = "NETWORK"
    elif "file" in src_lower or "$mft" in src_lower or "disk" in src_lower:
        resolved_type = "FILESYSTEM"

    parser_label = parser_info
    if source_name and source_name not in parser_label:
        parser_label = f"{parser_info} ({source_name})"

    # Check for existing artifact under this evidence
    existing = (
        db.query(Artifact)
        .filter(
            Artifact.evidence_id == evidence.evidence_id,
            Artifact.artifact_type == resolved_type,
            Artifact.parser_used == parser_label,
        )
        .first()
    )
    if existing:
        return existing

    # Create new artifact
    new_artifact = Artifact(
        evidence_id=evidence.evidence_id,
        artifact_type=resolved_type,
        parser_used=parser_label,
        raw_data=raw_info or {"source": source_name, "artifact": artifact_name},
    )
    db.add(new_artifact)
    db.flush()
    return new_artifact


def ingest_m1_payload(
    db: Session,
    payload: Dict[str, Any],
    evidence_id: Optional[str] = None,
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Ingests an M1 normalized output payload into the M3 SQLite database.
    - Validates payload contract
    - Verifies evidence identity and SHA-256 integrity
    - Creates or reuses Artifacts
    - Converts events to canonical representation while preserving original types and IDs
    - Employs batch insertion within a transaction
    - Deduplicates identical events on repeat ingestion
    - Rolls back safely on failure
    """
    validate_m1_payload(payload)

    # 1. Resolve Evidence Record
    resolved_ev_id = evidence_id or payload.get("evidence_id")
    evidence: Optional[Evidence] = None

    if resolved_ev_id:
        evidence = db.query(Evidence).filter(Evidence.evidence_id == resolved_ev_id).first()

    if not evidence and case_id:
        # Match by file name or hash if evidence_id was not directly matched
        input_file = payload.get("input_file")
        input_hash = payload.get("sha256")
        if input_file:
            evidence = (
                db.query(Evidence)
                .filter(Evidence.case_id == case_id, Evidence.source_name == input_file)
                .first()
            )
        if not evidence and input_hash:
            evidence = (
                db.query(Evidence)
                .filter(Evidence.case_id == case_id, Evidence.hash_sha256 == input_hash)
                .first()
            )

    if not evidence:
        raise IngestionError(
            f"Could not locate matching Evidence record for evidence_id '{resolved_ev_id}' "
            f"in case '{case_id}'"
        )

    # 2. Cryptographic SHA-256 Verification (where available)
    payload_sha256 = payload.get("sha256")
    if payload_sha256 and evidence.hash_sha256:
        if payload_sha256.lower() != evidence.hash_sha256.lower():
            raise IngestionError(
                f"Forensic SHA-256 hash mismatch! "
                f"Evidence record expects '{evidence.hash_sha256}', but M1 payload produced '{payload_sha256}'"
            )

    # 3. Query existing events for duplicate prevention
    existing_events = (
        db.query(Event.event_id, Event.source_event_id)
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .filter(Artifact.evidence_id == evidence.evidence_id)
        .all()
    )
    existing_ids = {row[0] for row in existing_events if row[0]}
    existing_source_ids = {row[1] for row in existing_events if row[1]}

    events_raw = payload.get("events", [])
    processors = payload.get("processors", [])
    processor_names = [p.get("tool") for p in processors if isinstance(p, dict) and p.get("tool")]
    default_parser = ", ".join(processor_names) if processor_names else "M1 Forensic Pipeline"

    # Artifact cache by (source, artifact_name)
    artifact_cache: Dict[Tuple[Optional[str], Optional[str]], Artifact] = {}

    # Query global event IDs to ensure primary key uniqueness across SQLite table
    global_existing_ids = {row[0] for row in db.query(Event.event_id).all()}

    new_events: List[Event] = []
    skipped_duplicates = 0

    try:
        for ev in events_raw:
            source_ev_id = str(ev.get("event_id"))
            if source_ev_id in existing_ids or source_ev_id in existing_source_ids:
                skipped_duplicates += 1
                continue

            src = ev.get("source")
            art = ev.get("artifact")
            cache_key = (src, art)

            if cache_key not in artifact_cache:
                artifact_obj = get_or_create_artifact(
                    db=db,
                    evidence=evidence,
                    artifact_name=art,
                    source_name=src,
                    parser_info=default_parser,
                    raw_info=ev.get("metadata"),
                )
                artifact_cache[cache_key] = artifact_obj
            else:
                artifact_obj = artifact_cache[cache_key]

            # Canonical Event Semantics
            raw_event_type = str(ev.get("event_type", "UNKNOWN"))
            canonical_type = map_canonical_event_type(raw_event_type)

            parsed_ts = parse_event_timestamp(ev.get("timestamp"))

            # Build enriched details preserving original forensic fields
            meta = dict(ev.get("metadata") or {})
            details: Dict[str, Any] = {
                **meta,
                "original_event_type": raw_event_type,
                "source_event_id": source_ev_id,
            }
            if ev.get("process"):
                details["process"] = ev["process"]
                if "image" not in details:
                    details["image"] = ev["process"]
            if ev.get("command_line"):
                details["command_line"] = ev["command_line"]
                if "CommandLine" not in details:
                    details["CommandLine"] = ev["command_line"]
            if ev.get("source_ip"):
                details["source_ip"] = ev["source_ip"]
                if "src_ip" not in details:
                    details["src_ip"] = ev["source_ip"]
            if ev.get("destination_ip"):
                details["destination_ip"] = ev["destination_ip"]
                if "dst_ip" not in details:
                    details["dst_ip"] = ev["destination_ip"]
            if ev.get("source_port") is not None:
                details["source_port"] = ev["source_port"]
                if "src_port" not in details:
                    details["src_port"] = ev["source_port"]
            if ev.get("destination_port") is not None:
                details["destination_port"] = ev["destination_port"]
                if "dst_port" not in details:
                    details["dst_port"] = ev["destination_port"]
            if ev.get("file_path"):
                details["file_path"] = ev["file_path"]
                if "target_filename" not in details:
                    details["target_filename"] = ev["file_path"]
            if ev.get("file_hash"):
                details["file_hash"] = ev["file_hash"]
                if "sha256_hash" not in details:
                    details["sha256_hash"] = ev["file_hash"]
            if ev.get("artifact"):
                details["artifact"] = ev["artifact"]
            if ev.get("action"):
                details["action"] = ev["action"]

            # Assign primary key: use source_ev_id if not taken, otherwise namespaced ID
            target_event_id = source_ev_id
            if target_event_id in global_existing_ids:
                target_event_id = f"{evidence.evidence_id[:8]}-{source_ev_id}"
                if target_event_id in global_existing_ids:
                    import uuid
                    target_event_id = str(uuid.uuid4())
            global_existing_ids.add(target_event_id)

            event_obj = Event(
                event_id=target_event_id,
                source_event_id=source_ev_id,
                artifact_id=artifact_obj.artifact_id,
                timestamp=parsed_ts,
                event_type=canonical_type,
                source_entity=src or art or evidence.source_name,
                user_account=ev.get("user"),
                host_ip=ev.get("host") or ev.get("source_ip"),
                details=details,
                is_anomalous=0,
                anomaly_score=0.0,
            )
            new_events.append(event_obj)
            existing_ids.add(target_event_id)
            existing_source_ids.add(source_ev_id)

        # 4. Batch Insertion in Database Transaction
        if new_events:
            db.add_all(new_events)
            db.flush()

        evidence.processing_status = "INGESTED"
        db.add(
            AuditLog(
                case_id=evidence.case_id,
                user_name="M3 Ingestion Service",
                action="M1_PAYLOAD_INGESTED",
                details=(
                    f"Ingested {len(new_events)} events from M1 for evidence {evidence.source_name}. "
                    f"Duplicates skipped: {skipped_duplicates}."
                ),
            )
        )
        db.commit()

    except Exception as exc:
        db.rollback()
        evidence.processing_status = "FAILED"
        evidence.processing_error = f"Ingestion failed: {exc}"
        db.commit()
        raise IngestionError(f"Database insertion failed during ingestion: {exc}") from exc

    return {
        "status": "INGESTED",
        "evidence_id": evidence.evidence_id,
        "case_id": evidence.case_id,
        "events_received": len(events_raw),
        "events_inserted": len(new_events),
        "duplicates_skipped": skipped_duplicates,
        "artifacts_count": len(artifact_cache),
    }
