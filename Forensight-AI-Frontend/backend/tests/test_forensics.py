import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.crypto import (
    compute_file_hashes,
    encrypt_report_payload,
    decrypt_report_payload
)

client = TestClient(app)


def test_root_status():
    """Verify backend health and active forensic modules."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert len(data["modules_active"]) == 7


def test_operation_blackout_seeded():
    """Verify Module 1: Case and Evidence Management with preloaded demo case."""
    response = client.get("/api/cases")
    assert response.status_code == 200
    cases = response.json()
    assert len(cases) >= 1
    case = cases[0]
    assert case["case_number"] == "FS-2026-001"
    assert "Operation Blackout" in case["case_name"]
    assert case["evidence_count"] == 4
    assert case["event_count"] >= 8


def test_evidence_integrity_verification():
    """Verify Module 1 & 2: SHA-256 evidence integrity validation."""
    cases = client.get("/api/cases").json()
    case_id = cases[0]["case_id"]

    evidence_res = client.get(f"/api/cases/{case_id}/evidence")
    assert evidence_res.status_code == 200
    ev_list = evidence_res.json()
    assert len(ev_list) == 4

    # Verify first evidence item
    ev_id = ev_list[0]["evidence_id"]
    verify_res = client.post(f"/api/evidence/{ev_id}/verify-integrity")
    assert verify_res.status_code == 200
    check_data = verify_res.json()
    assert check_data["is_valid"] is True
    assert "PASSED" in check_data["status"]


def test_chronological_timeline():
    """Verify Module 3: Chronological timeline and Common Event Model."""
    cases = client.get("/api/cases").json()
    case_id = cases[0]["case_id"]

    res = client.get(f"/api/cases/{case_id}/timeline")
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 8

    # Ensure events are chronological
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)

    # Test filtering only anomalous events
    anom_res = client.get(f"/api/cases/{case_id}/timeline?only_anomalous=true")
    assert anom_res.status_code == 200
    anom_events = anom_res.json()
    assert all(e["is_anomalous"] == 1 for e in anom_events)


def test_ai_investigation_assistant():
    """Verify Module 4: Evidence-grounded conversational RAG assistant with strict citations."""
    cases = client.get("/api/cases").json()
    case_id = cases[0]["case_id"]

    # Query 1: Incident summary
    summary_res = client.get(f"/api/ai/cases/{case_id}/summary")
    assert summary_res.status_code == 200
    summary_data = summary_res.json()
    assert len(summary_data["citations"]) > 0
    assert summary_data["confidence_score"] > 0.80

    # Query 2: Specific PowerShell query
    query_res = client.post("/api/ai/query", json={
        "case_id": case_id,
        "query": "Show suspicious PowerShell activity and commands"
    })
    assert query_res.status_code == 200
    q_data = query_res.json()
    assert "powershell" in q_data["response"].lower()
    assert len(q_data["citations"]) > 0
    # Every citation must include event_id and source_entity
    for cit in q_data["citations"]:
        assert "event_id" in cit
        assert "source_entity" in cit


def test_examiner_validation_gate():
    """Verify Module 5: Human-in-the-loop validation gate."""
    cases = client.get("/api/cases").json()
    case_id = cases[0]["case_id"]

    findings = client.get(f"/api/cases/{case_id}/findings").json()
    assert len(findings) >= 6
    target_finding = findings[0]

    # Examiner updates validation status
    val_res = client.patch(f"/api/findings/{target_finding['finding_id']}/validate", json={
        "validation_status": "Accepted",
        "investigator_notes": "Forensically validated by lead investigator Rohan Johny via MFT and EVTX cross-check."
    })
    assert val_res.status_code == 200
    updated = val_res.json()
    assert updated["validation_status"] == "Accepted"
    assert "Rohan Johny" in updated["investigator_notes"]


def test_attack_path_reconstruction():
    """Verify Module 5: Attack-path kill chain mapping to MITRE ATT&CK."""
    cases = client.get("/api/cases").json()
    case_id = cases[0]["case_id"]

    res = client.get(f"/api/cases/{case_id}/attack-path")
    assert res.status_code == 200
    data = res.json()
    assert data["total_stages"] >= 6
    stages = [s["stage_name"] for s in data["stages"]]
    assert "Initial Access" in stages
    assert "Execution" in stages
    assert "Persistence" in stages
    assert "Exfiltration" in stages


def test_two_key_cryptography_and_report_generation():
    """Verify Module 6 & 7: Report generation, Two-Key AES-256-GCM encryption, and tamper verification."""
    cases = client.get("/api/cases").json()
    case_id = cases[0]["case_id"]

    gen_res = client.post(f"/api/cases/{case_id}/reports/generate", json={
        "case_id": case_id,
        "report_name": "Operation Blackout - Courtroom Forensic Dossier",
        "investigator_name": "Rohan Johny (Lead Forensic Examiner)",
        "include_raw_hashes": True,
        "executive_summary": "Intrusion successfully investigated. Attack sequence fully reconstructed."
    })
    assert gen_res.status_code == 200
    rep = gen_res.json()
    assert rep["status"] == "Final"
    assert len(rep["integrity_hash"]) == 64  # SHA-256 hex string

    # Decrypt and verify tamper integrity (Module 7)
    dec_res = client.get(f"/api/reports/{rep['report_id']}/decrypt")
    assert dec_res.status_code == 200
    dec_data = dec_res.json()
    assert dec_data["is_tamper_free"] is True
    assert "FORENSIC INVESTIGATION REPORT" in dec_data["plaintext_content"]
    assert "Rohan Johny" in dec_data["plaintext_content"]
