from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from app.pipeline import process_file
from app.schemas.event_schema import TOP_LEVEL_FIELDS, NormalizedEvent


def test_end_to_end_plaso_csv_to_normalized_events(tmp_path: Path):
    """Verifies that actual Plaso CSV output is parsed, normalized into the
    17-field contract, and output as normalized_events.json and processing_manifest.json.
    """
    # Use real Plaso output from evidence if available, or sample plaso CSV
    real_csv = Path(r"D:\Project\test_evidence\drive1_plaso.csv")
    csv_to_test = real_csv if real_csv.exists() else Path("sample_data/plaso_l2tcsv_example.csv")

    case_dir = tmp_path / "case_acceptance"
    result = process_file(
        path=str(csv_to_test),
        output_dir=str(case_dir),
        kind="auto",
    )

    # 1. Output files exist
    json_path = case_dir / "normalized" / "normalized_events.json"
    jsonl_path = case_dir / "normalized" / "normalized_events.jsonl"
    manifest_path = case_dir / "processing_manifest.json"

    assert json_path.exists(), "normalized_events.json was not created"
    assert jsonl_path.exists(), "normalized_events.jsonl was not created"
    assert manifest_path.exists(), "processing_manifest.json was not created"

    # 2. Check JSON content & 17-field schema
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert "events" in data
    events = data["events"]
    assert len(events) > 0, "No events found in normalized output"

    for ev in events:
        # Strict validation
        NormalizedEvent.validate_dict(ev)
        assert tuple(ev.keys()) == TOP_LEVEL_FIELDS
        assert ev["event_id"].startswith("EVT-")
        assert isinstance(ev["metadata"], dict)
        # Ensure plaso_row is preserved for Plaso events
        assert "plaso_row" in ev["metadata"]
        assert isinstance(ev["metadata"]["plaso_row"], dict)

    # 3. Check processing manifest
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["case_id"] == "case_acceptance"
    assert "evidence_id" in manifest
    assert "sha256" in manifest
    assert "normalization" in manifest
    assert manifest["normalization"]["output_events"] == len(events)
    assert manifest["normalization"]["input_events"] >= len(events)


def test_real_evidence_drive1_pipeline_execution(tmp_path: Path):
    """Acceptance test: Run pipeline against drive1.E01 (if available) and verify full execution."""
    evidence_path = None
    for candidate in [
        os.getenv("EVIDENCE_DRIVE1_PATH"),
        r"C:\Users\rohan\Downloads\test_evidence_drive1.E01",
        r"C:\Users\rohan\Downloads\test_evidence_drive1",
        str(Path(__file__).resolve().parents[2] / "test_evidence" / "drive1.E01"),
        r"D:\Project\test_evidence\drive1.E01",
    ]:
        if candidate and Path(candidate).exists():
            evidence_path = Path(candidate)
            break

    if not evidence_path or not evidence_path.exists():
        pytest.skip("drive1.E01 real evidence file not found in test_evidence directory")

    case_dir = tmp_path / "case_test_drive1"
    result = process_file(
        path=str(evidence_path),
        output_dir=str(case_dir),
        kind="disk",
        timeline=True,
    )

    assert result["case_id"] == case_dir.name
    assert result["detected_type"] == "disk_image"
    assert (case_dir / "normalized" / "normalized_events.json").exists()
    assert (case_dir / "processing_manifest.json").exists()

    events = result["events"]
    assert len(events) > 0

    # Verify at least one tool ran successfully
    proc_statuses = [p["status"] for p in result["processors"]]
    assert "SUCCESS" in proc_statuses
