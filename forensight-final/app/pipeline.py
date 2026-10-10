from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path
from typing import Any

from app.constants import (
    STATUS_SUCCESS,
    STATUS_SKIPPED,
    STATUS_TOOL_FAILED,
    STATUS_TOOL_NOT_INSTALLED,
    STATUS_TOOL_TIMEOUT,
    EVIDENCE_TYPE_DISK_IMAGE,
    EVIDENCE_TYPE_MEMORY_DUMP,
    EVIDENCE_TYPE_NETWORK_CAPTURE,
    EVIDENCE_TYPE_WINDOWS_EVENT_LOG,
    EVIDENCE_TYPE_WINDOWS_REGISTRY,
    EVIDENCE_TYPE_STRUCTURED_EXPORT,
    EVIDENCE_TYPE_INDIVIDUAL_ARTIFACT,
)
from app.evidence_identifier import identify_evidence, ClassificationResult
from app.extractors.autopsy_reports import parse_autopsy_output
from app.extractors.volatility_extractor import parse_volatility_output
from app.extractors.csv_extractor import extract_csv
from app.extractors.json_extractor import extract_json
from app.extractors.plaso_extractor import extract_plaso_csv
from app.schemas.event_schema import NormalizedEvent
from app.tools.autopsy_runner import run_autopsy
from app.tools.plaso_runner import run_plaso
from app.tools.volatility_runner import run_volatility
from app.tools.detector import tool_status, get_autopsy_version, get_plaso_version, get_volatility_version
from app.utils.hashing import sha256_file, md5_file
from app.utils.normalize import normalize_raw_event


def _looks_like_plaso_csv(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            headers = next(reader, [])
    except OSError:
        return False
    normalized = {str(h).strip().lower() for h in headers}
    return {"date", "time", "macb", "source", "sourcetype", "type"}.issubset(normalized)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def parse_direct_input(path: str | Path) -> tuple[str, list[dict[str, Any]]]:
    p = Path(path)
    ext = p.suffix.lower()
    if ext == ".json":
        return "JSON", extract_json(p)
    if ext == ".jsonl":
        return "JSONL", _load_jsonl(p)
    if ext == ".csv":
        return "CSV", extract_csv(p)
    raise ValueError(f"Unsupported direct structured input: {p.name}")


def normalize_events(raw_events: list[dict[str, Any]], source: str) -> list[NormalizedEvent]:
    return [normalize_raw_event(item, source=source, index=i) for i, item in enumerate(raw_events)]


def deduplicate(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    seen = set()
    out: list[NormalizedEvent] = []
    for event in events:
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        out.append(event)
    return out


def _save_tool_result(root: Path, result: Any, tool_version: str | None = None) -> dict[str, Any]:
    tool_key = result.tool.lower().replace(" ", "_")
    out = root / "tool_outputs" / tool_key
    out.mkdir(parents=True, exist_ok=True)
    (out / "stdout.txt").write_text(result.stdout or "", encoding="utf-8", errors="replace")
    (out / "stderr.txt").write_text(result.stderr or "", encoding="utf-8", errors="replace")
    (out / "command.json").write_text(json.dumps(result.command, indent=2), encoding="utf-8")
    payload = {
        "tool": result.tool,
        "version": tool_version,
        "status": result.status,
        "available": result.available,
        "executed": result.executed,
        "returncode": result.returncode,
        "error": result.error,
        "output_dir": str(out),
    }
    (out / "status.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _skip_tool(name: str, reason: str, root: Path, tool_version: str | None = None) -> dict[str, Any]:
    tool_key = name.lower().replace(" ", "_")
    out = root / "tool_outputs" / tool_key
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": name,
        "version": tool_version,
        "status": STATUS_SKIPPED,
        "available": None,
        "executed": False,
        "returncode": None,
        "error": reason,
        "output_dir": str(out),
    }
    (out / "status.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def process_file(
    path: str | Path,
    output_dir: str | Path = "cases/case-001",
    kind: str = "auto",
    timeline: bool = True
) -> dict[str, Any]:
    """Classifies evidence, routes to the appropriate forensic processor(s),
    parses extracted artifacts, and normalizes into the 17-field schema.
    """
    source_path = Path(path).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {source_path}")

    case_root = Path(output_dir).resolve()
    case_id = case_root.name
    case_root.mkdir(parents=True, exist_ok=True)

    # 1. Initialize case directory structure
    (case_root / "evidence").mkdir(exist_ok=True)
    (case_root / "hashes").mkdir(exist_ok=True)
    (case_root / "tool_outputs").mkdir(exist_ok=True)
    (case_root / "normalized").mkdir(exist_ok=True)

    # 2. Evidence identification & hashing
    classification = identify_evidence(source_path, requested_kind=kind)
    source_sha256 = classification.hash
    source_md5 = md5_file(source_path) if source_path.is_file() else ""

    (case_root / "hashes" / "sha256.txt").write_text(f"{source_sha256}  {source_path.name}\n", encoding="utf-8")
    (case_root / "hashes" / "md5.txt").write_text(f"{source_md5}  {source_path.name}\n", encoding="utf-8")

    all_raw_events: list[dict[str, Any]] = []
    processors: list[dict[str, Any]] = []

    # 3. Direct structured inputs (JSON, JSONL, CSV)
    if classification.detected_type == EVIDENCE_TYPE_STRUCTURED_EXPORT:
        ext = source_path.suffix.lower()
        if ext == ".csv" and _looks_like_plaso_csv(source_path):
            source = "Plaso"
            raw = extract_plaso_csv(source_path)
        else:
            source, raw = parse_direct_input(source_path)
        all_raw_events.extend(raw)
        norm_events = normalize_events(all_raw_events, source=source)
        deduped_events = deduplicate(norm_events)
        dups = len(norm_events) - len(deduped_events)

        return _finalize_case(
            case_id=case_id,
            case_root=case_root,
            classification=classification,
            source_path=source_path,
            source_sha256=source_sha256,
            source_md5=source_md5,
            processors=[],
            raw_event_count=len(all_raw_events),
            events=deduped_events,
            duplicates_removed=dups,
            mode="direct_normalization",
        )

    # 4. Tool-based Routing
    detected_type = classification.detected_type

    if detected_type == EVIDENCE_TYPE_DISK_IMAGE:
        # Autopsy Ingest
        autopsy_dir = case_root / "tool_outputs" / "autopsy"
        import time
        r_auto = run_autopsy(str(source_path), str(autopsy_dir), case_name=f"Case_{case_id}_{int(time.time())}")
        processors.append(_save_tool_result(case_root, r_auto, tool_version=get_autopsy_version()))
        if r_auto.status == STATUS_SUCCESS:
            all_raw_events.extend(parse_autopsy_output(autopsy_dir))

        # Plaso Timeline
        if timeline:
            plaso_dir = case_root / "tool_outputs" / "plaso"
            r_plaso = run_plaso(str(source_path), str(plaso_dir))
            processors.append(_save_tool_result(case_root, r_plaso, tool_version=get_plaso_version()))
            csv_path = plaso_dir / "plaso_timeline.csv"
            if r_plaso.status == STATUS_SUCCESS and csv_path.exists():
                all_raw_events.extend(extract_plaso_csv(csv_path))
        else:
            processors.append(_skip_tool("Plaso", "Timeline extraction was explicitly disabled.", case_root, get_plaso_version()))

        # Volatility is not applicable
        processors.append(_skip_tool("Volatility 3", "Not applicable: input is disk image evidence.", case_root, get_volatility_version()))

    elif detected_type == EVIDENCE_TYPE_MEMORY_DUMP:
        processors.append(_skip_tool("Autopsy", "Not applicable: input is memory dump evidence.", case_root, get_autopsy_version()))
        processors.append(_skip_tool("Plaso", "Not applicable: input is memory dump evidence.", case_root, get_plaso_version()))

        vol_dir = case_root / "tool_outputs" / "volatility_3"
        r_vol = run_volatility(str(source_path), str(vol_dir))
        processors.append(_save_tool_result(case_root, r_vol, tool_version=get_volatility_version()))
        if r_vol.status == STATUS_SUCCESS:
            all_raw_events.extend(parse_volatility_output(vol_dir))

    elif detected_type in (
        EVIDENCE_TYPE_WINDOWS_EVENT_LOG,
        EVIDENCE_TYPE_WINDOWS_REGISTRY,
        EVIDENCE_TYPE_NETWORK_CAPTURE,
        EVIDENCE_TYPE_INDIVIDUAL_ARTIFACT,
    ):
        processors.append(_skip_tool("Autopsy", "Not applicable: input is an individual forensic artifact.", case_root, get_autopsy_version()))
        processors.append(_skip_tool("Volatility 3", "Not applicable: input is not a memory dump.", case_root, get_volatility_version()))

        plaso_dir = case_root / "tool_outputs" / "plaso"
        r_plaso = run_plaso(str(source_path), str(plaso_dir))
        processors.append(_save_tool_result(case_root, r_plaso, tool_version=get_plaso_version()))
        csv_path = plaso_dir / "plaso_timeline.csv"
        if r_plaso.status == STATUS_SUCCESS and csv_path.exists():
            all_raw_events.extend(extract_plaso_csv(csv_path))

    else:
        raise ValueError(
            f"Unsupported evidence type: '{detected_type}'. "
            "Please specify explicit processing parameters or route manually."
        )

    # 5. Normalization & Deduplication
    norm_events = normalize_events(all_raw_events, source=f"Forensic Extract ({classification.detected_type})")
    deduped_events = deduplicate(norm_events)
    dups = len(norm_events) - len(deduped_events)

    return _finalize_case(
        case_id=case_id,
        case_root=case_root,
        classification=classification,
        source_path=source_path,
        source_sha256=source_sha256,
        source_md5=source_md5,
        processors=processors,
        raw_event_count=len(all_raw_events),
        events=deduped_events,
        duplicates_removed=dups,
        mode="forensic_tool_routed",
    )


def _finalize_case(
    case_id: str,
    case_root: Path,
    classification: ClassificationResult,
    source_path: Path,
    source_sha256: str,
    source_md5: str,
    processors: list[dict[str, Any]],
    raw_event_count: int,
    events: list[NormalizedEvent],
    duplicates_removed: int,
    mode: str,
) -> dict[str, Any]:
    event_dicts = [e.to_dict() for e in events]

    # Save to normalized/
    norm_dir = case_root / "normalized"
    norm_dir.mkdir(parents=True, exist_ok=True)
    json_path = norm_dir / "normalized_events.json"
    json_path.write_text(json.dumps({"events": event_dicts}, indent=2, ensure_ascii=False), encoding="utf-8")

    jsonl_path = norm_dir / "normalized_events.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as f:
        for e in event_dicts:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    # Backward compatibility at case root
    (case_root / "normalized_events.json").write_text(json.dumps({"events": event_dicts}, indent=2, ensure_ascii=False), encoding="utf-8")
    (case_root / "normalized_events.jsonl").write_text(jsonl_path.read_text(encoding="utf-8"), encoding="utf-8")

    # Build processing manifest matching requirements
    manifest = {
        "case_id": case_id,
        "evidence_id": classification.evidence_id,
        "input_file": source_path.name,
        "input_path": str(source_path),
        "detected_type": classification.detected_type,
        "detected_format": classification.detected_format,
        "confidence": classification.confidence,
        "sha256": source_sha256,
        "md5": source_md5,
        "processors": processors,
        "normalization": {
            "input_events": raw_event_count,
            "output_events": len(event_dicts),
            "duplicates_removed": duplicates_removed,
        },
        "mode": mode,
        "installed_tools": tool_status(),
    }

    manifest_path = case_root / "processing_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        **manifest,
        "events": event_dicts,
        "event_count": len(event_dicts),
        "output_json": str(json_path),
        "output_jsonl": str(jsonl_path),
        "manifest_path": str(manifest_path),
    }
