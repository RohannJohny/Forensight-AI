from __future__ import annotations

import pytest
from pathlib import Path
from app.input_router import classify_input


def test_disk_routes_to_autopsy_and_plaso(tmp_path: Path):
    f = tmp_path / "evidence.E01"
    f.write_bytes(b"EVF\t\r\n\xff\x00" + b"\x00" * 100)
    route = classify_input(f)
    assert route.kind == "disk"
    assert route.primary_tools == ("Autopsy", "Plaso")


def test_memory_routes_to_volatility(tmp_path: Path):
    f = tmp_path / "ramdump.mem"
    f.write_bytes(b"\x00" * 1024)
    route = classify_input(f)
    assert route.kind == "memory"
    assert route.primary_tools == ("Volatility 3",)


def test_raw_ambiguous_requires_explicit_kind(tmp_path: Path):
    f = tmp_path / "evidence.raw"
    f.write_bytes(b"\x00" * 1024)
    # Ambiguous raw without partition table must not silently choose disk or memory
    with pytest.raises(ValueError, match="Ambiguous evidence"):
        classify_input(f)


def test_raw_can_be_explicitly_disk(tmp_path: Path):
    f = tmp_path / "evidence.raw"
    f.write_bytes(b"\x00" * 1024)
    route = classify_input(f, requested_kind="disk")
    assert route.kind == "disk"
    assert route.primary_tools == ("Autopsy", "Plaso")


def test_raw_can_be_explicitly_memory(tmp_path: Path):
    f = tmp_path / "evidence.raw"
    f.write_bytes(b"\x00" * 1024)
    route = classify_input(f, requested_kind="memory")
    assert route.kind == "memory"
    assert route.primary_tools == ("Volatility 3",)


def test_evtx_routes_to_plaso(tmp_path: Path):
    f = tmp_path / "Security.evtx"
    f.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
    route = classify_input(f)
    assert route.kind == "timeline"
    assert route.primary_tools == ("Plaso",)


def test_pcap_routes_to_plaso_best_effort(tmp_path: Path):
    f = tmp_path / "capture.pcapng"
    f.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 100)
    route = classify_input(f)
    assert route.kind == "packet"
    assert route.primary_tools == ("Plaso",)


def test_plaso_l2tcsv_is_detected_as_plaso_by_pipeline(tmp_path: Path):
    from app.pipeline import process_file
    sample = Path("sample_data/plaso_l2tcsv_example.csv")
    result = process_file(str(sample), tmp_path / "test-plaso-csv")
    assert result["detected_type"] == "structured_export"
    assert result["normalization"]["output_events"] == 3
    assert result["events"][0]["timestamp"] is None
    assert result["events"][0]["event_type"] == "FILE_MODIFIED"
    assert result["events"][0]["action"] == "modified"
