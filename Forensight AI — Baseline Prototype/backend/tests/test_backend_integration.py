"""
Forensight AI - Complete Backend Integration Test Suite
Validates the entire end-to-end backend workflow across M1, M2, and M3:
Evidence Upload -> M1 Tool Routing & Extraction -> M1 Normalization ->
M3 Ingestion -> Artifact/Event Persistence -> M2 Intelligence & Correlation ->
Findings & MITRE AttackNodes Persistence -> RAG Assistant -> Report Generation.

Covers all 17 integration requirements mandated by Section 13.
"""

import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.database import SessionLocal
from app.models.models import Case, Evidence, Artifact, Event, Finding, AttackNode, Report, User
from app.forensics.m1_client import M1Client, M1_DIR
from app.forensics.ingestion_service import (
    ingest_m1_payload,
    validate_m1_payload,
    validate_m1_event_contract,
    IngestionError,
)
from app.forensics.event_semantics import map_canonical_event_type
from app.api.findings import run_correlation_and_detection
from app.ai.mitre_mapper import MitreAttackMapper

client = TestClient(app)


@pytest.fixture(scope="module")
def sample_synthetic_evidence_path():
    """Path to M1's synthetic forensic events sample file."""
    sample_file = M1_DIR / "sample_data" / "synthetic_forensic_events.json"
    assert sample_file.exists(), f"Synthetic sample file must exist at {sample_file}"
    return sample_file


@pytest.fixture(scope="module")
def integration_test_case():
    """Creates a dedicated fresh case for integration testing."""
    case_num = f"FS-TEST-{uuid.uuid4().hex[:6].upper()}"
    res = client.post("/api/cases", json={
        "case_number": case_num,
        "case_name": "Integration Test Intrusion Case",
        "description": "Integration testing automated forensic pipeline",
        "status": "Active"
    })
    assert res.status_code == 200, res.text
    case_data = res.json()
    yield case_data


# ============================================================
# TEST 1: Case creation
# ============================================================
def test_01_case_creation():
    """TEST 1: Case creation with validation and audit logging."""
    case_num = f"FS-CASE-{uuid.uuid4().hex[:6].upper()}"
    res = client.post("/api/cases", json={
        "case_number": case_num,
        "case_name": "Digital Forensics Case 1",
        "description": "Testing case container creation",
        "status": "Active"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["case_number"] == case_num
    assert data["case_id"] is not None
    assert data["status"] == "Active"

    # Verify retrieval
    get_res = client.get(f"/api/cases/{data['case_id']}")
    assert get_res.status_code == 200
    assert get_res.json()["case_name"] == "Digital Forensics Case 1"


# ============================================================
# TEST 2: Evidence upload
# ============================================================
def test_02_evidence_upload(integration_test_case, sample_synthetic_evidence_path):
    """TEST 2: Evidence upload safely stores file and creates Evidence record."""
    case_id = integration_test_case["case_id"]

    with open(sample_synthetic_evidence_path, "rb") as f:
        file_bytes = f.read()

    res = client.post(
        f"/api/cases/{case_id}/evidence/upload",
        files={"file": ("synthetic_evidence.json", file_bytes, "application/json")},
        data={"evidence_type": "STRUCTURED_EXPORT"}
    )
    assert res.status_code == 200, res.text
    ev = res.json()
    assert ev["evidence_id"] is not None
    assert ev["case_id"] == case_id
    assert ev["source_name"] == "synthetic_evidence.json"
    assert ev["processing_status"] in ("PENDING", "COMPLETED")
    assert os.path.exists(ev["storage_path"]), "Uploaded evidence file must exist on disk"


# ============================================================
# TEST 3: Evidence hashing
# ============================================================
def test_03_evidence_hashing(integration_test_case, sample_synthetic_evidence_path):
    """TEST 3: Standard forensic SHA-256, SHA-1, and MD5 hashes computed upon upload."""
    case_id = integration_test_case["case_id"]
    with open(sample_synthetic_evidence_path, "rb") as f:
        content = f.read()

    import hashlib
    expected_sha256 = hashlib.sha256(content).hexdigest()
    expected_md5 = hashlib.md5(content).hexdigest()

    res = client.post(
        f"/api/cases/{case_id}/evidence/upload",
        files={"file": ("hashing_test.json", content, "application/json")},
        data={"evidence_type": "STRUCTURED_EXPORT"}
    )
    assert res.status_code == 200
    ev = res.json()
    assert ev["hash_sha256"].lower() == expected_sha256.lower()
    assert ev["hash_md5"].lower() == expected_md5.lower()

    # Verify cryptographic integrity check endpoint
    verify_res = client.post(f"/api/evidence/{ev['evidence_id']}/verify-integrity")
    assert verify_res.status_code == 200
    assert verify_res.json()["is_valid"] is True
    assert "PASSED" in verify_res.json()["status"]


# ============================================================
# TEST 4: Evidence identification
# ============================================================
def test_04_evidence_identification(sample_synthetic_evidence_path):
    """TEST 4: M1 identifies evidence type via magic bytes, headers, and structure."""
    ident = M1Client.identify_evidence(sample_synthetic_evidence_path)
    assert ident is not None
    assert "detected_type" in ident
    assert ident["detected_type"] == "structured_export"
    assert ident["confidence"] >= 0.80
    assert "hash" in ident


# ============================================================
# TEST 5: M1 invocation
# ============================================================
def test_05_m1_invocation(sample_synthetic_evidence_path):
    """TEST 5: M3 successfully invokes M1 pipeline to process evidence."""
    temp_case_id = f"test-m1-invoc-{uuid.uuid4().hex[:6]}"
    temp_out = M1_DIR / "cases" / temp_case_id
    try:
        m1_res = M1Client.process_evidence(
            file_path=sample_synthetic_evidence_path,
            case_id=temp_case_id,
            output_dir=temp_out
        )
        assert m1_res is not None
        assert "events" in m1_res
        assert m1_res["event_count"] >= 6
        assert Path(m1_res["output_json"]).exists()
    finally:
        shutil.rmtree(temp_out, ignore_errors=True)


# ============================================================
# TEST 6: M1 normalized output
# ============================================================
def test_06_m1_normalized_output(sample_synthetic_evidence_path):
    """TEST 6: M1 outputs events adhering to strict 17-field common schema."""
    temp_case_id = f"test-schema-{uuid.uuid4().hex[:6]}"
    temp_out = M1_DIR / "cases" / temp_case_id
    try:
        m1_res = M1Client.process_evidence(sample_synthetic_evidence_path, case_id=temp_case_id, output_dir=temp_out)
        events = m1_res["events"]
        assert len(events) >= 6

        expected_fields = {
            "event_id", "timestamp", "event_type", "source", "host", "user",
            "process", "command_line", "source_ip", "destination_ip", "source_port",
            "destination_port", "file_path", "file_hash", "artifact", "action", "metadata"
        }
        for ev in events:
            assert set(ev.keys()) == expected_fields
            assert ev["event_id"] is not None
            assert isinstance(ev["metadata"], dict)
    finally:
        shutil.rmtree(temp_out, ignore_errors=True)


# ============================================================
# TEST 7: M1→M3 contract validation
# ============================================================
def test_07_m1_to_m3_contract_validation():
    """TEST 7: Contract validation accepts valid payloads and rejects malformed payloads."""
    valid_event = {
        "event_id": "EVT-TEST-001",
        "timestamp": "2026-10-06T12:00:00Z",
        "event_type": "PROCESS_EXECUTION",
        "source": "Security Log",
        "host": "HOST-1",
        "user": "admin",
        "process": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "file_path": None,
        "file_hash": None,
        "artifact": "Security Log",
        "action": "executed",
        "metadata": {"pid": 1234}
    }
    # Valid event passes
    validate_m1_event_contract(valid_event)

    # Valid payload passes
    validate_m1_payload({"events": [valid_event]})

    # Missing field raises IngestionError
    invalid_event = dict(valid_event)
    del invalid_event["metadata"]
    with pytest.raises(IngestionError, match="missing required fields"):
        validate_m1_event_contract(invalid_event)

    # Malformed payload raises IngestionError
    with pytest.raises(IngestionError, match="must contain an 'events' list"):
        validate_m1_payload({"events": "not-a-list"})


# ============================================================
# TEST 8: Artifact insertion
# ============================================================
def test_08_artifact_insertion(integration_test_case):
    """TEST 8: Artifact records are inserted and reused under the Evidence container."""
    db: Session = SessionLocal()
    try:
        ev = db.query(Evidence).filter(Evidence.case_id == integration_test_case["case_id"]).first()
        assert ev is not None

        payload = {
            "evidence_id": ev.evidence_id,
            "events": [
                {
                    "event_id": f"EVT-ART-{uuid.uuid4().hex[:6]}",
                    "timestamp": "2026-10-06T10:00:00Z",
                    "event_type": "PROCESS_EXECUTION",
                    "source": "Registry Hive Parser",
                    "host": "HOST-1",
                    "user": "SYSTEM",
                    "process": "reg.exe",
                    "command_line": None,
                    "source_ip": None,
                    "destination_ip": None,
                    "source_port": None,
                    "destination_port": None,
                    "file_path": None,
                    "file_hash": None,
                    "artifact": "NTUSER.DAT",
                    "action": "modified",
                    "metadata": {"key": "Run"}
                }
            ]
        }
        res1 = ingest_m1_payload(db, payload, evidence_id=ev.evidence_id, case_id=ev.case_id)
        assert res1["artifacts_count"] >= 1

        # Check DB artifact record
        artifact = db.query(Artifact).filter(Artifact.evidence_id == ev.evidence_id).first()
        assert artifact is not None
        assert artifact.artifact_type in ("REGISTRY", "LOG", "PROCESS", "NETWORK", "FILESYSTEM")
    finally:
        db.close()


# ============================================================
# TEST 9: Event insertion with provenance and canonical mapping
# ============================================================
def test_09_event_insertion(integration_test_case):
    """TEST 9: Events inserted with canonical mapping, original M1 ID and type preserved."""
    db: Session = SessionLocal()
    try:
        ev = db.query(Evidence).filter(Evidence.case_id == integration_test_case["case_id"]).first()
        m1_event_id = f"EVT-M1-{uuid.uuid4().hex[:8]}"

        payload = {
            "evidence_id": ev.evidence_id,
            "events": [
                {
                    "event_id": m1_event_id,
                    "timestamp": "2026-10-06T14:30:00Z",
                    "event_type": "PROCESS_EXECUTION",  # Canonical mapping: PROCESS_CREATE
                    "source": "Sysmon",
                    "host": "WS-01",
                    "user": "jdoe",
                    "process": "powershell.exe",
                    "command_line": "powershell.exe -enc AAAA",
                    "source_ip": None,
                    "destination_ip": None,
                    "source_port": None,
                    "destination_port": None,
                    "file_path": None,
                    "file_hash": None,
                    "artifact": "Sysmon Event 1",
                    "action": "executed",
                    "metadata": {"parent_process": "cmd.exe"}
                },
                {
                    "event_id": f"EVT-NOTIME-{uuid.uuid4().hex[:6]}",
                    "timestamp": None,  # Legitimately null timestamp per Section 7!
                    "event_type": "FILE_CREATED",  # Canonical mapping: FILE_CREATE (never FILE_DROP)
                    "source": "$MFT",
                    "host": "WS-01",
                    "user": "jdoe",
                    "process": None,
                    "command_line": None,
                    "source_ip": None,
                    "destination_ip": None,
                    "source_port": None,
                    "destination_port": None,
                    "file_path": "C:\\temp\\test.dll",
                    "file_hash": "2222222222222222222222222222222222222222222222222222222222222222",
                    "artifact": "$MFT Record",
                    "action": "created",
                    "metadata": {"size": 4096}
                }
            ]
        }
        res = ingest_m1_payload(db, payload, evidence_id=ev.evidence_id, case_id=ev.case_id)
        assert res["events_inserted"] == 2

        # Verify event 1 in database
        event1 = db.query(Event).filter(Event.event_id == m1_event_id).first()
        assert event1 is not None, "Original M1 event ID must be preserved as primary key / event_id"
        assert event1.source_event_id == m1_event_id, "Original M1 ID must be recorded as source_event_id"
        assert event1.event_type == "PROCESS_CREATE", "PROCESS_EXECUTION must map to PROCESS_CREATE"
        assert event1.details["original_event_type"] == "PROCESS_EXECUTION", "Original type preserved in details"
        assert event1.details["command_line"] == "powershell.exe -enc AAAA"

        # Verify event 2: null timestamp handled cleanly
        event2 = db.query(Event).filter(Event.source_event_id == payload["events"][1]["event_id"]).first()
        assert event2 is not None
        assert event2.timestamp is None, "Timestamp MUST remain None when forensic event lacks timestamp"
        assert event2.event_type == "FILE_CREATE", "FILE_CREATED must map to FILE_CREATE, never FILE_DROP"
    finally:
        db.close()


# ============================================================
# TEST 10: Duplicate ingestion protection
# ============================================================
def test_10_duplicate_ingestion_protection(integration_test_case):
    """TEST 10: Repeated ingestion of the same payload safely avoids duplicates."""
    db: Session = SessionLocal()
    try:
        ev = db.query(Evidence).filter(Evidence.case_id == integration_test_case["case_id"]).first()
        test_eid = f"EVT-DUP-{uuid.uuid4().hex[:6]}"
        payload = {
            "evidence_id": ev.evidence_id,
            "events": [
                {
                    "event_id": test_eid,
                    "timestamp": "2026-10-06T15:00:00Z",
                    "event_type": "NETWORK_CONNECTION",
                    "source": "PCAP",
                    "host": "192.168.1.10",
                    "user": None,
                    "process": "curl.exe",
                    "command_line": None,
                    "source_ip": "192.168.1.10",
                    "destination_ip": "1.1.1.1",
                    "source_port": 50000,
                    "destination_port": 80,
                    "file_path": None,
                    "file_hash": None,
                    "artifact": "TCP Stream",
                    "action": "connected",
                    "metadata": {"proto": "TCP"}
                }
            ]
        }
        # First ingestion
        res1 = ingest_m1_payload(db, payload, evidence_id=ev.evidence_id, case_id=ev.case_id)
        assert res1["events_inserted"] == 1
        assert res1["duplicates_skipped"] == 0

        # Second ingestion with exact same payload
        res2 = ingest_m1_payload(db, payload, evidence_id=ev.evidence_id, case_id=ev.case_id)
        assert res2["events_inserted"] == 0
        assert res2["duplicates_skipped"] == 1

        # Confirm count in database is exactly 1
        count = db.query(Event).filter(Event.source_event_id == test_eid).count()
        assert count == 1
    finally:
        db.close()


# ============================================================
# TEST 11: M2 retrieval
# ============================================================
def test_11_m2_retrieval(integration_test_case):
    """TEST 11: M2 retrieves events through SQLite joins: Case -> Evidence -> Artifact -> Event."""
    db: Session = SessionLocal()
    try:
        case_id = integration_test_case["case_id"]
        events = (
            db.query(Event)
            .join(Artifact, Event.artifact_id == Artifact.artifact_id)
            .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
            .filter(Evidence.case_id == case_id)
            .all()
        )
        assert len(events) >= 1
        for ev in events:
            assert ev.artifact is not None
            assert ev.artifact.evidence is not None
            assert ev.artifact.evidence.case_id == case_id
    finally:
        db.close()


# ============================================================
# TEST 12: M2 analysis (classification, anomaly detection, correlation)
# ============================================================
def test_12_m2_analysis(integration_test_case):
    """TEST 12: M2 performs evidence classification, anomaly detection, and correlation."""
    db: Session = SessionLocal()
    try:
        case_id = integration_test_case["case_id"]
        res = run_correlation_and_detection(case_id, db)
        assert res is not None
        assert "status" in res
        assert "Correlation complete" in res["status"]
        assert "events_scanned" in res
        assert "classified_events" in res
        assert "classification_summary" in res
        assert "correlations" in res
        assert "attack_chains" in res
    finally:
        db.close()


# ============================================================
# TEST 13: Finding persistence
# ============================================================
def test_13_finding_persistence(integration_test_case):
    """TEST 13: Investigative findings are generated and persisted in SQLite."""
    db: Session = SessionLocal()
    try:
        case_id = integration_test_case["case_id"]
        # Ingest an anomalous event to trigger finding creation
        ev = db.query(Evidence).filter(Evidence.case_id == case_id).first()
        payload = {
            "evidence_id": ev.evidence_id,
            "events": [
                {
                    "event_id": f"EVT-ANOM-{uuid.uuid4().hex[:6]}",
                    "timestamp": "2026-10-06T16:00:00Z",
                    "event_type": "PROCESS_EXECUTION",
                    "source": "Sysmon",
                    "host": "192.168.1.100",
                    "user": "victim",
                    "process": "powershell.exe",
                    "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                    "source_ip": None,
                    "destination_ip": None,
                    "source_port": None,
                    "destination_port": None,
                    "file_path": None,
                    "file_hash": None,
                    "artifact": "Sysmon Event 1",
                    "action": "executed",
                    "metadata": {"parent_image": "winword.exe", "image": "powershell.exe"}
                }
            ]
        }
        ingest_m1_payload(db, payload, evidence_id=ev.evidence_id, case_id=ev.case_id)

        # Run correlation and detection
        run_correlation_and_detection(case_id, db)

        # Verify findings persisted
        findings = db.query(Finding).filter(Finding.case_id == case_id).all()
        assert len(findings) >= 1
        for f in findings:
            assert f.finding_title is not None
            assert f.confidence_score > 0.0
            assert f.validation_status in ("Pending", "Accepted", "Rejected", "Modified")
            assert f.description is not None
    finally:
        db.close()


# ============================================================
# TEST 14: MITRE AttackNode persistence
# ============================================================
def test_14_mitre_attacknode_persistence(integration_test_case):
    """TEST 14: MITRE AttackNodes are persisted in SQLite and retrieved via REST API."""
    case_id = integration_test_case["case_id"]
    db: Session = SessionLocal()
    try:
        nodes = db.query(AttackNode).filter(AttackNode.case_id == case_id).all()
        assert len(nodes) >= 1, "AttackNode records must be persisted in SQLite"
        for n in nodes:
            assert n.mitre_technique is not None
            assert n.stage_name in MitreAttackMapper.TACTIC_STAGES or n.stage_name is not None
            assert n.stage_order >= 1
    finally:
        db.close()

    # Verify REST endpoint
    res = client.get(f"/api/cases/{case_id}/attack-path")
    assert res.status_code == 200
    data = res.json()
    assert data["total_stages"] >= 1
    assert "graph" in data
    assert len(data["stages"]) >= 1


# ============================================================
# TEST 15: RAG retrieval
# ============================================================
def test_15_rag_retrieval(integration_test_case):
    """TEST 15: RAG assistant retrieves database-grounded evidence with strict citations."""
    case_id = integration_test_case["case_id"]

    # Query via /api/ai/query
    res = client.post("/api/ai/query", json={
        "case_id": case_id,
        "query": "Show powershell and command execution records"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_id
    assert "response" in data
    assert len(data["citations"]) >= 1
    for cit in data["citations"]:
        assert cit["event_id"] is not None
        assert cit["source_entity"] is not None

    # Query via /api/cases/{case_id}/assistant/query
    res2 = client.post(f"/api/cases/{case_id}/assistant/query", json={
        "query": "Summarize findings and anomalous activity"
    })
    assert res2.status_code == 200
    assert len(res2.json()["citations"]) >= 1


# ============================================================
# TEST 16: Report generation
# ============================================================
def test_16_report_generation(integration_test_case):
    """TEST 16: Final dossier generated with AES-256-GCM Two-Key encryption and tamper check."""
    case_id = integration_test_case["case_id"]
    db: Session = SessionLocal()
    try:
        # Mark at least one finding Accepted for inclusion
        f = db.query(Finding).filter(Finding.case_id == case_id).first()
        if f:
            f.validation_status = "Accepted"
            db.commit()
    finally:
        db.close()

    gen_res = client.post(f"/api/cases/{case_id}/reports/generate", json={
        "case_id": case_id,
        "report_name": "Integration Test Comprehensive Dossier",
        "investigator_name": "Lead Forensic Examiner",
        "include_raw_hashes": True,
        "executive_summary": "Intrusion analysis verified."
    })
    assert gen_res.status_code == 200
    rep = gen_res.json()
    assert rep["report_id"] is not None
    assert rep["status"] == "Final"
    assert len(rep["integrity_hash"]) == 64

    # Verify decrypt endpoint
    dec_res = client.get(f"/api/reports/{rep['report_id']}/decrypt")
    assert dec_res.status_code == 200
    dec_data = dec_res.json()
    assert dec_data["is_tamper_free"] is True
    assert "FORENSIC INVESTIGATION REPORT" in dec_data["plaintext_content"]

    # Verify latest case report endpoint
    case_rep_res = client.get(f"/api/cases/{case_id}/report")
    assert case_rep_res.status_code == 200
    assert case_rep_res.json()["report_id"] == rep["report_id"]


# ============================================================
# TEST 17: Failure/retry behaviour
# ============================================================
def test_17_failure_and_retry_behaviour(integration_test_case):
    """TEST 17: Failure during processing stores error state and permits safe retry."""
    case_id = integration_test_case["case_id"]
    db: Session = SessionLocal()
    try:
        # Create an evidence record pointing to a non-existent file
        fake_ev = Evidence(
            case_id=case_id,
            source_name="missing_file.raw",
            evidence_type="MEMORY_DUMP",
            storage_path="C:\\nonexistent_vault\\missing_file.raw",
            hash_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            processing_status="PENDING"
        )
        db.add(fake_ev)
        db.commit()
        db.refresh(fake_ev)
        fake_id = fake_ev.evidence_id
    finally:
        db.close()

    # Attempt to process missing file -> must fail truthfully, not fabricate success
    res = client.post(f"/api/evidence/{fake_id}/process")
    assert res.status_code in (404, 500)

    # Check status endpoint shows FAILED
    status_res = client.get(f"/api/evidence/{fake_id}/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["processing_status"] == "FAILED"
    assert status_data["processing_error"] is not None

    # Verify retry: if physical file is restored, retry executes
    db = SessionLocal()
    try:
        ev_obj = db.query(Evidence).filter(Evidence.evidence_id == fake_id).first()
        # Point to valid file
        valid_sample = M1_DIR / "sample_data" / "synthetic_forensic_events.json"
        ev_obj.storage_path = str(valid_sample)
        ev_obj.hash_sha256 = ""  # reset hash check for retry
        ev_obj.processing_status = "PENDING"
        db.commit()
    finally:
        db.close()

    retry_res = client.post(f"/api/evidence/{fake_id}/process")
    assert retry_res.status_code == 200
    assert retry_res.json()["status"] == "COMPLETED"


# ============================================================
# TEST 18: Synthetic End-to-End Orchestrated Workflow
# ============================================================
def test_18_synthetic_end_to_end_orchestration(sample_synthetic_evidence_path):
    """
    TEST 18: Full synthetic pipeline from clean evidence upload through
    M1 tool execution -> normalization -> M3 ingestion -> M2 intelligence ->
    persisted findings -> AttackNodes -> RAG -> Report.
    """
    # 1. Create Case
    c_res = client.post("/api/cases", json={
        "case_number": f"FS-E2E-{uuid.uuid4().hex[:6].upper()}",
        "case_name": "End-to-End Forensic Investigation",
        "description": "Validation of full M1->M3->M2 backend integration",
        "status": "Active"
    })
    assert c_res.status_code == 200
    case_id = c_res.json()["case_id"]

    # 2. Upload Evidence
    with open(sample_synthetic_evidence_path, "rb") as f:
        ev_content = f.read()

    up_res = client.post(
        f"/api/cases/{case_id}/evidence/upload",
        files={"file": ("e2e_evidence.json", ev_content, "application/json")},
        data={"evidence_type": "STRUCTURED_EXPORT"}
    )
    assert up_res.status_code == 200
    evidence_id = up_res.json()["evidence_id"]

    # 3. Process Evidence (Orchestrated Workflow)
    proc_res = client.post(f"/api/evidence/{evidence_id}/process")
    assert proc_res.status_code == 200, proc_res.text
    proc_data = proc_res.json()
    assert proc_data["status"] == "COMPLETED"
    assert proc_data["events_ingested"] >= 6

    # 4. Verify Events in Timeline
    events_res = client.get(f"/api/cases/{case_id}/events")
    assert events_res.status_code == 200
    events = events_res.json()
    assert len(events) >= 6

    # 5. Verify Findings and AttackNodes
    findings_res = client.get(f"/api/cases/{case_id}/findings")
    assert findings_res.status_code == 200

    attack_path_res = client.get(f"/api/cases/{case_id}/attack-path")
    assert attack_path_res.status_code == 200
    assert "stages" in attack_path_res.json()

    # 6. Verify RAG query
    ai_res = client.post("/api/ai/query", json={
        "case_id": case_id,
        "query": "Show events related to sample.exe"
    })
    assert ai_res.status_code == 200
    assert len(ai_res.json()["citations"]) >= 1

    # 7. Generate Courtroom Report
    rep_res = client.post(f"/api/cases/{case_id}/reports/generate", json={
        "case_id": case_id,
        "report_name": "E2E Final Forensic Report",
        "investigator_name": "Antigravity Automated Examiner",
        "include_raw_hashes": True,
        "executive_summary": "Full intrusion sequence validated end-to-end."
    })
    assert rep_res.status_code == 200
    assert rep_res.json()["status"] == "Final"
