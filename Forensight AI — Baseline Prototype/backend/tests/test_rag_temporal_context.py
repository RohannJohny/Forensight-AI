import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal
from app.models.models import Case, Event, Finding, Artifact, Evidence
from app.ai.rag_assistant import EvidenceGroundedAssistant

client = TestClient(app)


@pytest.fixture
def blackout_case_data():
    """Load the seeded Operation Blackout case, normalized events, and findings."""
    db = SessionLocal()
    case = db.query(Case).filter(Case.case_number == "FS-2026-001").first()
    assert case is not None, "Operation Blackout case FS-2026-001 must be seeded."

    events = (
        db.query(Event)
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case.case_id)
        .all()
    )
    findings = db.query(Finding).filter(Finding.case_id == case.case_id).all()
    yield case, events, findings
    db.close()


def test_temporal_query_expands_context(blackout_case_data):
    """Test A: Temporal query expands context chronologically and includes preceding archive activity."""
    case, events, findings = blackout_case_data
    query = "What evidence indicates data exfiltration and what activity preceded it?"

    # 1. Direct Assistant invocation
    result = EvidenceGroundedAssistant.query(case, events, findings, query)

    citation_ids = [c["event_id"] for c in result["citations"]]
    assert len(result["citations"]) >= 2, "Expected at least 2 citations (preceding staging + exfiltration)"

    # Identify preceding archive event and exfiltration event
    archive_events = [
        ev for ev in events
        if ev.event_type == "PROCESS_CREATE" and "7z" in str(ev.details)
    ]
    exfil_events = [
        ev for ev in events
        if ev.event_type == "NETWORK_CONNECTION" and ev.details.get("bytes_transferred") == 88604672
    ]
    assert len(archive_events) == 1
    assert len(exfil_events) == 1

    archive_ev = archive_events[0]
    exfil_ev = exfil_events[0]

    # Verify both event IDs appear in citations
    assert archive_ev.event_id in citation_ids
    assert exfil_ev.event_id in citation_ids

    # Verify chronological ordering in citations (archive at 09:42:10 before exfil at 09:44:18)
    assert result["citations"][0]["event_id"] == archive_ev.event_id
    assert result["citations"][1]["event_id"] == exfil_ev.event_id

    # Verify chronological ordering in narrative response
    pos_archive = result["response"].find("09:42:10")
    pos_exfil = result["response"].find("09:44:18")
    assert pos_archive != -1, "Expected 09:42:10 archive event in response"
    assert pos_exfil != -1, "Expected 09:44:18 exfiltration event in response"
    assert pos_archive < pos_exfil, "Expected chronological ordering (archive preceding exfiltration)"

    # Verify details are present
    assert "cmd.exe" in result["response"]
    assert "7z" in result["response"]
    assert "fin_q3_confidential.7z" in result["response"]
    assert "198.51.100.88:443" in result["response"]
    assert "88604672" in result["response"]
    assert "cdn-cloud-storage.external-relay.net" in result["response"]

    # Verify no unsupported claim that the archive was definitely the transferred payload
    assert "do not independently prove that the archive itself was the transferred payload" in result["response"]
    assert "definitely the transferred payload" not in result["response"]

    # Verify grounding note is preserved
    assert "This response is limited to retrieved case records. It does not infer facts that are absent from the evidence." in result["response"]

    # 2. End-to-end API test via /api/ai/query
    api_res = client.post("/api/ai/query", json={
        "case_id": case.case_id,
        "query": query,
    })
    assert api_res.status_code == 200
    api_data = api_res.json()
    api_citation_ids = [c["event_id"] for c in api_data["citations"]]
    assert archive_ev.event_id in api_citation_ids
    assert exfil_ev.event_id in api_citation_ids


def test_focused_exfiltration_query_remains_focused(blackout_case_data):
    """Test B: Focused exfiltration query remains focused and does not automatically add preceding event."""
    case, events, findings = blackout_case_data
    query = "data exfiltration"

    result = EvidenceGroundedAssistant.query(case, events, findings, query)

    # Focused query must not trigger temporal expansion
    assert len(result["citations"]) == 1
    assert result["citations"][0]["summary"].startswith("[NETWORK_CONNECTION]")
    assert "198.51.100.88" in result["citations"][0]["summary"]

    # 09:42:10 archive event must NOT be present
    assert "09:42:10" not in result["response"]
    assert "7z" not in result["response"]
    assert "Temporal Context:" not in result["response"]


def test_no_unsupported_temporal_context(blackout_case_data):
    """Test C: When no relevant preceding event exists, do not invent events or unsupported temporal claims."""
    case, events, findings = blackout_case_data

    # Scenario: only the exfiltration event is supplied in the events list
    exfil_ev = [
        ev for ev in events
        if ev.event_type == "NETWORK_CONNECTION" and ev.details.get("bytes_transferred") == 88604672
    ][0]

    query = "What evidence indicates data exfiltration and what activity preceded it?"
    result = EvidenceGroundedAssistant.query(case, [exfil_ev], findings, query)

    # Should only return the 1 supplied event
    assert len(result["citations"]) == 1
    assert result["citations"][0]["event_id"] == exfil_ev.event_id

    # Must not invent a preceding event or claim a temporal sequence occurred
    assert "Temporal Context:" not in result["response"]
    assert "approximately two minutes" not in result["response"]


def test_existing_rag_behavior_remains_intact(blackout_case_data):
    """Test D: Standard queries and incident summary remain functional and evidence-grounded."""
    case, events, findings = blackout_case_data

    # 1. Non-temporal PowerShell query
    ps_result = EvidenceGroundedAssistant.query(case, events, findings, "Show suspicious PowerShell activity and commands")
    assert len(ps_result["citations"]) >= 1
    assert any("powershell" in c["summary"].lower() for c in ps_result["citations"])
    assert "Temporal Context:" not in ps_result["response"]

    # 2. Case summary query
    summary_result = EvidenceGroundedAssistant.query(case, events, findings, "Summarize the complete incident timeline and attack sequence")
    assert len(summary_result["citations"]) >= 1
    assert summary_result["confidence_score"] > 0.80
