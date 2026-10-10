from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

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
from app.utils.hashing import sha256_file


REGISTRY_HIVE_NAMES = {
    "ntuser.dat",
    "sam",
    "system",
    "software",
    "security",
    "default",
    "usrclass.dat",
    "components",
    "bcd",
}

DISK_EXTENSIONS = {
    ".e01", ".ex01", ".s01", ".aff", ".aff4", ".img", ".dd",
    ".001", ".002", ".vmdk", ".vhd", ".vhdx", ".qcow2"
}
MEMORY_EXTENSIONS = {".mem", ".vmem", ".dmp", ".lime", ".crash"}
NETWORK_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
LOG_EXTENSIONS = {".evtx", ".evt", ".etl", ".log"}
STRUCTURED_EXTENSIONS = {".json", ".jsonl", ".csv", ".xml"}


@dataclass(frozen=True)
class ClassificationResult:
    evidence_id: str
    filename: str
    detected_type: str
    confidence: float
    file_size: int
    hash: str
    detected_format: str
    recommended_processor: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _check_mbr(header: bytes) -> bool:
    if len(header) < 512:
        return False
    if header[510:512] != b"\x55\xaa":
        return False
    # Check partition table entries at offset 446..510 (4 entries of 16 bytes)
    valid_entries = 0
    for i in range(4):
        offset = 446 + i * 16
        part = header[offset:offset + 16]
        boot_flag = part[0]
        part_type = part[4]
        # Valid MBR boot flag is 0x00 or 0x80; partition type is non-zero
        if boot_flag in (0x00, 0x80) and part_type != 0:
            valid_entries += 1
    return valid_entries > 0


def _check_gpt(header: bytes) -> bool:
    if len(header) >= 520 and header[512:520] == b"EFI PART":
        return True
    return False


def _check_filesystem_boot_record(header: bytes) -> str | None:
    if len(header) < 512:
        return None
    if header[3:11] == b"NTFS    ":
        return "NTFS"
    if header[54:62].startswith(b"FAT") or header[82:90].startswith(b"FAT32") or header[3:11] == b"MSDOS5.0":
        return "FAT"
    if len(header) >= 1082 and header[1080:1082] == b"\x53\xef":
        return "EXT"
    if len(header) >= 32774 and header[32769:32774] == b"CD001":
        return "ISO9660"
    return None


def _check_structured_text(path: Path) -> tuple[str, str] | None:
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            first_chunk = f.read(4096).strip()
    except Exception:
        return None

    if not first_chunk:
        return None

    # Check JSON
    if (first_chunk.startswith("{") and "}" in first_chunk) or (first_chunk.startswith("[") and "]" in first_chunk):
        try:
            with open(path, "r", encoding="utf-8") as f:
                json.load(f)
            return "json", "direct_normalizer"
        except Exception:
            pass

    # Check JSONL
    lines = [l.strip() for l in first_chunk.splitlines() if l.strip()]
    if lines and all(l.startswith("{") and l.endswith("}") for l in lines[:3]):
        try:
            json.loads(lines[0])
            return "jsonl", "direct_normalizer"
        except Exception:
            pass

    # Check XML
    if first_chunk.startswith("<?xml") or (first_chunk.startswith("<") and ">" in first_chunk):
        return "xml", "direct_normalizer"

    # Check CSV
    if "," in lines[0] or "\t" in lines[0] or ";" in lines[0]:
        try:
            with open(path, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if header and len(header) >= 2:
                    return "csv", "direct_normalizer"
        except Exception:
            pass

    return None


def identify_evidence(
    path: str | Path,
    requested_kind: str = "auto"
) -> ClassificationResult:
    """Inspects and classifies uploaded evidence based on reliable forensic indicators.
    
    Examines file signatures, headers, container structures, metadata, and hash.
    Ambiguous inputs are explicitly marked rather than defaulted to dangerous tools.
    """
    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Evidence file not found: {p}")

    file_size = p.stat().st_size
    file_hash = sha256_file(p) if p.is_file() else ""
    evidence_id = f"EVD-{file_hash[:12].upper()}" if file_hash else f"EVD-{p.name}"
    ext = p.suffix.lower()
    name_lower = p.name.lower()

    # Read header bytes safely
    header = b""
    if p.is_file() and file_size > 0:
        try:
            with open(p, "rb") as f:
                header = f.read(65536)
        except OSError:
            header = b""

    # Explicit user override handling
    kind = requested_kind.lower().strip()
    if kind != "auto":
        if kind == "disk":
            return ClassificationResult(
                evidence_id=evidence_id,
                filename=p.name,
                detected_type=EVIDENCE_TYPE_DISK_IMAGE,
                confidence=1.0,
                file_size=file_size,
                hash=file_hash,
                detected_format="user_specified_disk",
                recommended_processor="autopsy_and_plaso",
                metadata={"user_override": True, "requested_kind": kind},
            )
        elif kind == "memory":
            return ClassificationResult(
                evidence_id=evidence_id,
                filename=p.name,
                detected_type=EVIDENCE_TYPE_MEMORY_DUMP,
                confidence=1.0,
                file_size=file_size,
                hash=file_hash,
                detected_format="user_specified_memory",
                recommended_processor="volatility_3",
                metadata={"user_override": True, "requested_kind": kind},
            )
        elif kind == "timeline":
            return ClassificationResult(
                evidence_id=evidence_id,
                filename=p.name,
                detected_type=EVIDENCE_TYPE_INDIVIDUAL_ARTIFACT,
                confidence=1.0,
                file_size=file_size,
                hash=file_hash,
                detected_format="user_specified_timeline",
                recommended_processor="plaso",
                metadata={"user_override": True, "requested_kind": kind},
            )
        elif kind == "packet":
            return ClassificationResult(
                evidence_id=evidence_id,
                filename=p.name,
                detected_type=EVIDENCE_TYPE_NETWORK_CAPTURE,
                confidence=1.0,
                file_size=file_size,
                hash=file_hash,
                detected_format="user_specified_packet",
                recommended_processor="plaso_best_effort",
                metadata={"user_override": True, "requested_kind": kind},
            )

    # 1. Forensic Containers & Disk Images (Magic Bytes)
    if len(header) >= 8 and header[:8] == b"EVF\t\r\n\xff\x00":
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.99,
            file_size=file_size,
            hash=file_hash,
            detected_format="E01 (Expert Witness Compression Format)",
            recommended_processor="autopsy_and_plaso",
            metadata={"header_signature": "EVF_E01"},
        )

    if len(header) >= 4 and header[:4] == b"EVF2":
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.99,
            file_size=file_size,
            hash=file_hash,
            detected_format="EX01 (Expert Witness Format 2)",
            recommended_processor="autopsy_and_plaso",
            metadata={"header_signature": "EVF2"},
        )

    if len(header) >= 4 and header[:4] == b"AFF\x00":
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.98,
            file_size=file_size,
            hash=file_hash,
            detected_format="AFF (Advanced Forensic Format)",
            recommended_processor="autopsy_and_plaso",
            metadata={"header_signature": "AFF"},
        )

    if len(header) >= 4 and header[:4] == b"KDMV":
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.98,
            file_size=file_size,
            hash=file_hash,
            detected_format="VMDK (Virtual Machine Disk)",
            recommended_processor="autopsy_and_plaso",
            metadata={"header_signature": "VMDK_KDMV"},
        )

    if header.startswith(b"# Disk DescriptorFile"):
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.95,
            file_size=file_size,
            hash=file_hash,
            detected_format="VMDK Descriptor File",
            recommended_processor="autopsy_and_plaso",
            metadata={"descriptor": True},
        )

    if header.startswith(b"conectix"):
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.95,
            file_size=file_size,
            hash=file_hash,
            detected_format="VHD (Virtual Hard Disk)",
            recommended_processor="autopsy_and_plaso",
            metadata={"header_signature": "conectix"},
        )

    if header.startswith(b"vhdxfile"):
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.95,
            file_size=file_size,
            hash=file_hash,
            detected_format="VHDX (Hyper-V Virtual Hard Disk)",
            recommended_processor="autopsy_and_plaso",
            metadata={"header_signature": "vhdxfile"},
        )

    if len(header) >= 4 and header[:4] == b"QFI\xfb":
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.98,
            file_size=file_size,
            hash=file_hash,
            detected_format="QCOW2 Disk Image",
            recommended_processor="autopsy_and_plaso",
            metadata={"header_signature": "QFI"},
        )

    # 2. Windows Event Logs (.evtx)
    if len(header) >= 8 and header[:8] == b"ElfFile\x00":
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_WINDOWS_EVENT_LOG,
            confidence=0.99,
            file_size=file_size,
            hash=file_hash,
            detected_format="EVTX (Windows XML Event Log)",
            recommended_processor="plaso",
            metadata={"header_signature": "ElfFile"},
        )

    # 3. Network Captures (PCAP / PCAPNG)
    if len(header) >= 4:
        pcap_magic = header[:4]
        if pcap_magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            return ClassificationResult(
                evidence_id=evidence_id,
                filename=p.name,
                detected_type=EVIDENCE_TYPE_NETWORK_CAPTURE,
                confidence=0.99,
                file_size=file_size,
                hash=file_hash,
                detected_format="PCAP Network Capture",
                recommended_processor="plaso_best_effort",
                metadata={"header_signature": "PCAP"},
            )
        if pcap_magic == b"\x0a\x0d\x0d\x0a":
            return ClassificationResult(
                evidence_id=evidence_id,
                filename=p.name,
                detected_type=EVIDENCE_TYPE_NETWORK_CAPTURE,
                confidence=0.99,
                file_size=file_size,
                hash=file_hash,
                detected_format="PCAPNG Network Capture",
                recommended_processor="plaso_best_effort",
                metadata={"header_signature": "PCAPNG"},
            )

    # 4. Windows Registry Hives
    if len(header) >= 4 and header[:4] == b"regf":
        hive_name = p.name.upper()
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_WINDOWS_REGISTRY,
            confidence=0.99,
            file_size=file_size,
            hash=file_hash,
            detected_format=f"Windows Registry Hive ({hive_name})",
            recommended_processor="plaso",
            metadata={"header_signature": "regf", "hive": hive_name},
        )

    if name_lower in REGISTRY_HIVE_NAMES:
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_WINDOWS_REGISTRY,
            confidence=0.90,
            file_size=file_size,
            hash=file_hash,
            detected_format=f"Windows Registry Hive ({p.name})",
            recommended_processor="plaso",
            metadata={"known_hive_name": True},
        )

    # 5. Memory Dumps
    if header.startswith(b"PAGE-DUMP") or header.startswith(b"PAGEDUMP"):
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_MEMORY_DUMP,
            confidence=0.99,
            file_size=file_size,
            hash=file_hash,
            detected_format="Windows Crash Dump",
            recommended_processor="volatility_3",
            metadata={"header_signature": "PAGEDUMP"},
        )

    if header.startswith(b"EMiL") or header.startswith(b"LiME"):
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_MEMORY_DUMP,
            confidence=0.99,
            file_size=file_size,
            hash=file_hash,
            detected_format="LiME Linux Memory Dump",
            recommended_processor="volatility_3",
            metadata={"header_signature": "LiME"},
        )

    if ext == ".vmem" or ext in {".mem", ".dmp", ".lime"}:
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_MEMORY_DUMP,
            confidence=0.92,
            file_size=file_size,
            hash=file_hash,
            detected_format=f"Memory Dump ({ext})",
            recommended_processor="volatility_3",
            metadata={"memory_extension": ext},
        )

    # 6. Specific Forensic Artifact Signatures
    if len(header) >= 8 and (header[4:8] == b"SCCA" or header[:4] == b"MAM\x04"):
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_INDIVIDUAL_ARTIFACT,
            confidence=0.98,
            file_size=file_size,
            hash=file_hash,
            detected_format="Windows Prefetch (.pf)",
            recommended_processor="plaso",
            metadata={"artifact": "Prefetch"},
        )

    if len(header) >= 16 and header[:16] == b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00":
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_INDIVIDUAL_ARTIFACT,
            confidence=0.98,
            file_size=file_size,
            hash=file_hash,
            detected_format="Windows Shortcut (.lnk)",
            recommended_processor="plaso",
            metadata={"artifact": "LNK"},
        )

    if header.startswith(b"SQLite format 3\x00"):
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_INDIVIDUAL_ARTIFACT,
            confidence=0.95,
            file_size=file_size,
            hash=file_hash,
            detected_format="SQLite Forensic Database",
            recommended_processor="plaso",
            metadata={"artifact": "SQLite"},
        )

    # 7. Structural Disk Image Inspection (MBR, GPT, Filesystems)
    is_mbr = _check_mbr(header)
    is_gpt = _check_gpt(header)
    fs_name = _check_filesystem_boot_record(header)

    if is_mbr or is_gpt or fs_name:
        detail = []
        if is_mbr:
            detail.append("MBR Partition Table")
        if is_gpt:
            detail.append("GPT Partition Table")
        if fs_name:
            detail.append(f"{fs_name} Filesystem")
        desc = " + ".join(detail)

        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.95,
            file_size=file_size,
            hash=file_hash,
            detected_format=f"Raw Storage Media ({desc})",
            recommended_processor="autopsy_and_plaso",
            metadata={"mbr": is_mbr, "gpt": is_gpt, "filesystem": fs_name},
        )

    # 8. Structured Forensic Exports
    structured = _check_structured_text(p)
    if structured:
        fmt, proc = structured
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_STRUCTURED_EXPORT,
            confidence=0.95,
            file_size=file_size,
            hash=file_hash,
            detected_format=f"Structured Forensic Data ({fmt.upper()})",
            recommended_processor=proc,
            metadata={"structured_format": fmt},
        )

    # 9. Ambiguity and Fallback Handling for .raw and others
    if ext == ".raw":
        # .raw could be either disk or memory, but has no partition table or filesystem signature
        # Check filename tokens for hints
        if any(tok in name_lower for tok in ("mem", "ram", "memory", "dump")):
            return ClassificationResult(
                evidence_id=evidence_id,
                filename=p.name,
                detected_type=EVIDENCE_TYPE_MEMORY_DUMP,
                confidence=0.75,
                file_size=file_size,
                hash=file_hash,
                detected_format="Raw Memory Image (heuristic)",
                recommended_processor="volatility_3",
                metadata={"heuristic": "filename_contains_memory_token"},
            )
        # Truly ambiguous .raw
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_AMBIGUOUS,
            confidence=0.45,
            file_size=file_size,
            hash=file_hash,
            detected_format="Ambiguous Raw Binary (.raw)",
            recommended_processor="manual_selection_required",
            metadata={"reason": ".raw without recognized partition table or memory signature. Specify --kind disk or --kind memory."},
        )

    # Extension-based fallback if format wasn't recognized by magic bytes
    if ext in DISK_EXTENSIONS:
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_DISK_IMAGE,
            confidence=0.70,
            file_size=file_size,
            hash=file_hash,
            detected_format=f"Disk Image ({ext})",
            recommended_processor="autopsy_and_plaso",
            metadata={"fallback": "extension"},
        )

    if ext in LOG_EXTENSIONS:
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_WINDOWS_EVENT_LOG,
            confidence=0.70,
            file_size=file_size,
            hash=file_hash,
            detected_format=f"Log File ({ext})",
            recommended_processor="plaso",
            metadata={"fallback": "extension"},
        )

    if ext in NETWORK_EXTENSIONS:
        return ClassificationResult(
            evidence_id=evidence_id,
            filename=p.name,
            detected_type=EVIDENCE_TYPE_NETWORK_CAPTURE,
            confidence=0.70,
            file_size=file_size,
            hash=file_hash,
            detected_format=f"Network Capture ({ext})",
            recommended_processor="plaso_best_effort",
            metadata={"fallback": "extension"},
        )

    # 10. Completely Unknown Evidence
    return ClassificationResult(
        evidence_id=evidence_id,
        filename=p.name,
        detected_type=EVIDENCE_TYPE_UNKNOWN,
        confidence=0.10,
        file_size=file_size,
        hash=file_hash,
        detected_format="Unrecognized Evidence Format",
        recommended_processor="none",
        metadata={"reason": "Unrecognized signature and extension; require explicit processor selection."},
    )
