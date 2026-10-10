# Forensight AI — Evidence Ingestion, Extraction & Normalization

This module is a clean, self-contained forensic evidence ingestion, extraction, and normalization pipeline for **Forensight AI**. It classifies uploaded evidence, routes it to genuine forensic processors (Autopsy / Sleuth Kit, Plaso, Volatility 3), parses raw outputs, and normalizes all extracted events into a strict 17-field common schema for downstream AI/ML consumption.

---

## 1. Architecture

```text
                    USER UPLOADS EVIDENCE
                            │
                            ▼
                  Evidence Intake Layer
                            │
                            ▼
                 Evidence Type Identifier
                            │
            ┌───────────────┼────────────────┐
            │               │                │
            ▼               ▼                ▼
        Disk Image       Memory Dump     Individual
        / Forensic       / Memory File    Artifacts
        Container             │                │
            │                 │                │
            ▼                 ▼                ▼
        Autopsy /          Volatility 3     Artifact-
        Sleuth Kit                         specific
            │                                  parsers
            └───────────────┬──────────────────┘
                            │
                            ▼
                    Plaso / Timeline
                    where applicable
                            │
                            ▼
                 Extraction / Parsing
                            │
                            ▼
                     Normalization
                            │
                            ▼
                Common Event Schema
                            │
                            ▼
                  normalized_events
                            │
                            ▼
              Downstream Forensight AI
```

### Core Architectural Principles

1. **Classification Before Processing**: Evidence is inspected using magic bytes, headers, structural signatures, and metadata before any processor is invoked.
2. **Ambiguity Safety**: Ambiguous inputs (e.g. raw binaries without partition tables or memory signatures) are marked as ambiguous and require explicit selection (`--kind disk` or `--kind memory`) rather than silently defaulting to dangerous processors.
3. **Genuine Forensic Tool Execution**: Autopsy, Plaso, and Volatility 3 are executed as real forensic tools; no mocked functions or simulated outputs exist in production paths.
4. **Normalized Common Schema**: Output events adhere strictly to the 17-field contract with complete forensic provenance preserved under `metadata`.
5. **No AI/LLM in this Stage**: Responsible strictly for evidence → extraction → parsing → normalization.

---

## 2. Evidence Classification Layer

When a file is uploaded, `identify_evidence()` inspects:
- **File Signatures / Magic Bytes**:
  - Disk Images: `.E01` / `.EX01` (`EVF`), `.AFF` / `.AFF4`, `.VMDK` (`KDMV`), `.VHD` (`conectix`), `.VHDX` (`vhdxfile`), `.QCOW2` (`QFI`)
  - Memory Dumps: Windows Crash Dumps (`PAGE-DUMP` / `PAGEDUMP`), LiME Linux Memory Dumps (`EMiL`), `.vmem`, `.mem`, `.dmp`
  - Windows Event Logs: `.evtx` (`ElfFile\x00`)
  - Network Captures: `.pcap` (`\xd4\xc3\xb2\xa1` / `\xa1\xb2\xc3\xd4`), `.pcapng` (`\x0a\x0d\x0d\x0a`)
  - Windows Registry Hives: `regf` header (`NTUSER.DAT`, `SAM`, `SYSTEM`, `SOFTWARE`, `SECURITY`, `DEFAULT`)
  - Forensic Artifacts: Prefetch (`SCCA` / `MAM`), Shortcuts (`.lnk`), SQLite (`SQLite format 3`)
  - Structured Exports: `.json`, `.jsonl`, `.csv`, `.xml`
- **Structural Validation**: MBR partition tables (`0x55AA` + partition records), GPT headers (`EFI PART`), and filesystem boot records (NTFS, FAT, Ext).

### Classification Result Contract

```json
{
  "evidence_id": "EVD-8E3B3F093D6C",
  "filename": "drive1.E01",
  "detected_type": "disk_image",
  "confidence": 0.99,
  "file_size": 2394116,
  "hash": "8e3b3f093d6ca4daf15e3cb7038d6734273c4387df2b8d6d588b6e5eba33f615",
  "detected_format": "E01 (Expert Witness Compression Format)",
  "recommended_processor": "autopsy_and_plaso",
  "metadata": {
    "header_signature": "EVF_E01"
  }
}
```

---

## 3. Forensic Tools Integration

| Tool | Executable / Method | Input Evidence | Harvested Output | Status Reporting |
|---|---|---|---|---|
| **Autopsy / Sleuth Kit** | `autopsy64.exe` CLI ingest (`--createCase`, `--addDataSource`, `--runIngest`) | Disk images (`.E01`, `.raw`, `.img`, etc.) | Parses `autopsy.db` SQLite (timeline `tsk_events`, filesystem `tsk_files`, blackboard artifacts `blackboard_artifacts`) | `AVAILABLE`, `NOT_INSTALLED`, `FAILED`, `TIMEOUT`, `SUCCESS` |
| **Plaso** | `psteal.exe` (`--source`, `-o l2tcsv`, `-w`) | Disk images, logs (`.evtx`), registry hives, artifacts | `plaso_timeline.csv` (hashes extracted from `extra`/`desc`, paths normalized, `metadata.plaso_row` preserved) | `AVAILABLE`, `NOT_INSTALLED`, `FAILED`, `TIMEOUT`, `SUCCESS` |
| **Volatility 3** | `vol.exe` / `python -m volatility3.cli` (`-q -r jsonl -f <source> <plugin>`) | Memory dumps (`.vmem`, `.dmp`, `.mem`, `.raw`) | `windows.info`, `windows.pslist`, `windows.pstree`, `windows.cmdline`, `windows.netscan` | `AVAILABLE`, `NOT_INSTALLED`, `FAILED`, `TIMEOUT`, `SUCCESS` |

---

## 4. Fresh Machine Setup

### Automated Windows Setup

Run the included setup script:

```powershell
.\setup.ps1
```

The setup script automatically:
1. Verifies Python 3.10+
2. Creates `.venv` virtual environment
3. Installs dependencies from `requirements.txt`
4. Runs `setup\verify_environment.py`
5. Discovers forensic tools and executes smoke tests (`setup\configure_tools.py`)
6. Stores resolved paths in `config/forensight.json` (no hardcoded developer paths!)
7. Runs the smoke test suite and reports tool status

### Manual Setup

```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
python setup/verify_environment.py
python setup/configure_tools.py
pytest tests/ -v
```

---

## 5. Usage & CLI

### Check Tool Availability

```powershell
python -m app.cli tools
```

### Identify Evidence

```powershell
python -m app.cli identify path\to\evidence.E01
```

### Route Evidence

```powershell
python -m app.cli route path\to\evidence.E01
```

### Process Evidence

```powershell
python -m app.cli process path\to\evidence.E01 --output cases/case-001
```

---

## 6. Output Organization & Processing Manifest

Each case produces an isolated directory structure:

```text
cases/
└── case-001/
    ├── evidence/
    ├── hashes/
    │   ├── sha256.txt
    │   └── md5.txt
    ├── tool_outputs/
    │   ├── autopsy/
    │   ├── plaso/
    │   └── volatility_3/
    ├── normalized/
    │   ├── normalized_events.json
    │   └── normalized_events.jsonl
    └── processing_manifest.json
```

### Common Event Schema (17 Top-Level Fields)

```json
{
  "event_id": "EVT-EDB6A6B13C36",
  "timestamp": "2026-10-05T10:32:41Z",
  "event_type": "FILE_MODIFIED",
  "source": "FILE",
  "host": "HOST01",
  "user": "john",
  "process": null,
  "command_line": null,
  "source_ip": null,
  "destination_ip": null,
  "source_port": null,
  "destination_port": null,
  "file_path": "\\Windows\\Enterprise.xml",
  "file_hash": "aadd044abcfef4646c76c32b3fb3ede7c5368e20ac70e26b5996e3a7e95e04ab",
  "artifact": "FILE (File stat)",
  "action": "modified",
  "metadata": {
    "plaso_row": {
      "date": "10/05/2026",
      "time": "10:32:41",
      "timezone": "UTC",
      "source": "FILE",
      "sourcetype": "File stat",
      "type": "Content Modification Time",
      "filename": "FAT:\\Windows\\Enterprise.xml"
    }
  }
}
```

### Processing Manifest

```json
{
  "case_id": "case-001",
  "evidence_id": "EVD-8E3B3F093D6C",
  "input_file": "drive1.E01",
  "detected_type": "disk_image",
  "detected_format": "E01 (Expert Witness Compression Format)",
  "sha256": "8e3b3f093d6ca4daf15e3cb7038d6734273c4387df2b8d6d588b6e5eba33f615",
  "processors": [
    {
      "tool": "Autopsy",
      "version": "4.23.1",
      "status": "SUCCESS"
    },
    {
      "tool": "Plaso",
      "version": "20260720",
      "status": "SUCCESS"
    },
    {
      "tool": "Volatility 3",
      "version": "2.28.2",
      "status": "SKIPPED_NOT_APPLICABLE"
    }
  ],
  "normalization": {
    "input_events": 433,
    "output_events": 433,
    "duplicates_removed": 0
  }
}
```

---

## 7. REST API

Start the FastAPI server:

```powershell
uvicorn app.main:app --reload --port 8000
```

Available endpoints:
- `GET /health` — Service health
- `GET /tools` — Detected forensic tools and statuses
- `POST /identify` — Upload file for evidence identification
- `POST /route` — Route uploaded evidence
- `POST /process` — Process evidence through the full pipeline
- `POST /normalize` — Direct JSON payload normalization
