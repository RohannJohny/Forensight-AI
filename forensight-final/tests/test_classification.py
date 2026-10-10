from __future__ import annotations

from pathlib import Path
import pytest

from app.constants import (
    EVIDENCE_TYPE_DISK_IMAGE,
    EVIDENCE_TYPE_MEMORY_DUMP,
    EVIDENCE_TYPE_NETWORK_CAPTURE,
    EVIDENCE_TYPE_WINDOWS_EVENT_LOG,
    EVIDENCE_TYPE_WINDOWS_REGISTRY,
    EVIDENCE_TYPE_STRUCTURED_EXPORT,
    EVIDENCE_TYPE_AMBIGUOUS,
    EVIDENCE_TYPE_UNKNOWN,
)
from app.evidence_identifier import identify_evidence


def test_classify_e01_magic(tmp_path: Path):
    f = tmp_path / "disk.E01"
    f.write_bytes(b"EVF\t\r\n\xff\x00" + b"\x00" * 512)
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_DISK_IMAGE
    assert res.confidence >= 0.95
    assert res.recommended_processor == "autopsy_and_plaso"
    assert res.hash != ""
    assert res.evidence_id.startswith("EVD-")
    assert res.filename == "disk.E01"


def test_classify_vmem_memory(tmp_path: Path):
    f = tmp_path / "sample.vmem"
    f.write_bytes(b"\x00" * 4096)
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_MEMORY_DUMP
    assert res.recommended_processor == "volatility_3"


def test_classify_crash_dump(tmp_path: Path):
    f = tmp_path / "memory.dmp"
    f.write_bytes(b"PAGE-DUMP" + b"\x00" * 1024)
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_MEMORY_DUMP
    assert res.recommended_processor == "volatility_3"
    assert "Crash Dump" in res.detected_format


def test_classify_evtx(tmp_path: Path):
    f = tmp_path / "System.evtx"
    f.write_bytes(b"ElfFile\x00" + b"\x00" * 1024)
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_WINDOWS_EVENT_LOG
    assert res.confidence == 0.99
    assert res.recommended_processor == "plaso"


def test_classify_pcap(tmp_path: Path):
    f = tmp_path / "traffic.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 1024)
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_NETWORK_CAPTURE
    assert res.confidence == 0.99


def test_classify_pcapng(tmp_path: Path):
    f = tmp_path / "traffic.pcapng"
    f.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 1024)
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_NETWORK_CAPTURE
    assert res.confidence == 0.99


def test_classify_registry_hive_magic(tmp_path: Path):
    f = tmp_path / "NTUSER.DAT"
    f.write_bytes(b"regf" + b"\x00" * 4096)
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_WINDOWS_REGISTRY
    assert res.confidence >= 0.95


def test_classify_structured_json(tmp_path: Path):
    f = tmp_path / "events.json"
    f.write_text('{"events": [{"event_id": "1", "event_type": "TEST"}]}', encoding="utf-8")
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_STRUCTURED_EXPORT
    assert res.recommended_processor == "direct_normalizer"


def test_classify_mbr_partitioned_raw(tmp_path: Path):
    f = tmp_path / "disk.raw"
    # Construct an MBR sector with 0x55AA and a valid partition table entry
    mbr = bytearray(512)
    mbr[510] = 0x55
    mbr[511] = 0xAA
    mbr[446] = 0x80  # active boot flag
    mbr[450] = 0x07  # NTFS partition type
    f.write_bytes(bytes(mbr))
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_DISK_IMAGE
    assert res.recommended_processor == "autopsy_and_plaso"


def test_classify_ambiguous_raw(tmp_path: Path):
    f = tmp_path / "unknown.raw"
    f.write_bytes(b"\x00" * 2048)  # zeroes, no partition table or memory signature
    res = identify_evidence(f)
    assert res.detected_type == EVIDENCE_TYPE_AMBIGUOUS
    assert res.recommended_processor == "manual_selection_required"
    assert res.confidence < 0.5


def test_all_eight_fields_present(tmp_path: Path):
    f = tmp_path / "test.E01"
    f.write_bytes(b"EVF\t\r\n\xff\x00" + b"\x00" * 100)
    res = identify_evidence(f)
    d = res.to_dict()
    required_fields = [
        "evidence_id",
        "filename",
        "detected_type",
        "confidence",
        "file_size",
        "hash",
        "detected_format",
        "recommended_processor",
    ]
    for field in required_fields:
        assert field in d
        assert d[field] is not None
