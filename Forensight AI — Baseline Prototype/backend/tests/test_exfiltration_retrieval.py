import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal
from app.models.models import Case, Event, Artifact, Evidence
from app.ai.retriever import retrieve_events

client = TestClient(app)


@pytest.fixture(scope="module")
def blackout_case_and_events():
    """Load the seeded Operation Blackout case and normalized events."""
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
    assert len(events) >= 8, "Expected at least 8 forensic events in Blackout case."
    db.close()
    return case, events


def test_data_exfiltration_retrieves_outbound_transfer_event(blackout_case_and_events):
    """Regression Test 1: 'data exfiltration' retrieves the Blackout outbound-transfer event."""
    case, events = blackout_case_and_events

    # 1. Direct unit-level retrieval test
    results = retrieve_events(events, "data exfiltration")
    assert len(results) >= 1, "Expected 'data exfiltration' to retrieve at least 1 event"

    top_event, top_score = results[0]
    assert top_event.event_type == "NETWORK_CONNECTION"
    assert top_event.details is not None
    assert top_event.details.get("bytes_transferred") == 88604672
    assert top_event.details.get("dst_ip") == "198.51.100.88"
    assert top_score >= 0.08

    # 2. End-to-end API retrieval test via /api/ai/query
    api_res = client.post("/api/ai/query", json={
        "case_id": case.case_id,
        "query": "data exfiltration"
    })
    assert api_res.status_code == 200
    data = api_res.json()
    assert len(data["citations"]) >= 1
    citation_event_ids = [c["event_id"] for c in data["citations"]]
    assert top_event.event_id in citation_event_ids
    assert "198.51.100.88" in data["response"] or "88604672" in data["response"] or "NETWORK_CONNECTION" in data["response"]


def test_powershell_retrieval_still_works(blackout_case_and_events):
    """Regression Test 2: 'PowerShell' retrieval continues to work."""
    case, events = blackout_case_and_events

    # 1. Direct unit-level retrieval test
    results = retrieve_events(events, "PowerShell")
    assert len(results) >= 1, "Expected 'PowerShell' query to retrieve events"

    top_event, top_score = results[0]
    assert top_event.event_type == "PROCESS_CREATE"
    cmd_or_img = str(top_event.details.get("image", "")) + str(top_event.details.get("command_line", ""))
    assert "powershell" in cmd_or_img.lower()
    assert top_score >= 0.08

    # 2. End-to-end API retrieval test
    api_res = client.post("/api/ai/query", json={
        "case_id": case.case_id,
        "query": "PowerShell"
    })
    assert api_res.status_code == 200
    data = api_res.json()
    assert len(data["citations"]) >= 1
    assert "powershell" in data["response"].lower()


def test_persistence_retrieval_still_works(blackout_case_and_events):
    """Regression Test 3: 'persistence' retrieval continues to work."""
    case, events = blackout_case_and_events

    # 1. Direct unit-level retrieval test
    results = retrieve_events(events, "persistence")
    assert len(results) >= 1, "Expected 'persistence' query to retrieve events"

    top_event, top_score = results[0]
    assert top_event.event_type == "REGISTRY_PERSISTENCE"
    assert "run" in str(top_event.details.get("key_path", "")).lower()
    assert top_score >= 0.08

    # 2. End-to-end API retrieval test
    api_res = client.post("/api/ai/query", json={
        "case_id": case.case_id,
        "query": "persistence"
    })
    assert api_res.status_code == 200
    data = api_res.json()
    assert len(data["citations"]) >= 1
    assert "REGISTRY_PERSISTENCE" in data["response"] or "registry" in data["response"].lower()


def test_generic_terms_do_not_over_retrieve(blackout_case_and_events):
    """Regression Test 4: Generic terms like 'destination' do not independently retrieve every network event."""
    case, events = blackout_case_and_events

    # Querying 'destination' must not retrieve all network events
    dest_results = retrieve_events(events, "destination")
    assert len(dest_results) == 0

    # Querying 'data exfiltration' must retrieve the large outbound transfer, but not the internal SMB connection
    exfil_results = retrieve_events(events, "data exfiltration")
    retrieved_types = [ev.event_type for ev, _ in exfil_results]
    assert all(t == "NETWORK_CONNECTION" for t in retrieved_types)
    for ev, _ in exfil_results:
        # Must be the outbound transfer event, not the internal SMB lateral movement event
        assert ev.details.get("dst_ip") != "192.168.1.150"
