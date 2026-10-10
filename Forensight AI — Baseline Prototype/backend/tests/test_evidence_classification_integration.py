from types import SimpleNamespace

from app.api.findings import (
    classify_events_for_m2,
    build_finding_explanation,
    create_finding_from_event,
)


def test_m2_classification_is_connected_to_event_pipeline():
    """Verify the pipeline helper classifies normalized events without mutation."""
    events = [
        SimpleNamespace(
            event_id="EV-001",
            event_type="PROCESS_CREATE",
            details={
                "image": "powershell.exe",
                "command_line": "powershell.exe -EncodedCommand AAAA",
            },
        ),
        SimpleNamespace(
            event_id="EV-002",
            event_type="NETWORK_CONNECTION",
            details={
                "dst_ip": "203.0.113.10",
                "bytes_transferred": 88_000_000,
            },
        ),
    ]

    classifications, summary = classify_events_for_m2(events)

    assert len(classifications) == 2
    assert classifications["EV-001"]["primary_category"] == "PROCESS_EXECUTION"
    assert "PROCESS_EXECUTION" in classifications["EV-001"]["categories"]
    assert classifications["EV-002"]["primary_category"] == "NETWORK_ACTIVITY"
    assert "DATA_EXFILTRATION" in classifications["EV-002"]["categories"]
    assert summary["PROCESS_EXECUTION"] == 1
    assert summary["NETWORK_ACTIVITY"] == 1
    assert summary["DATA_EXFILTRATION"] == 1

    # Classification must not mutate the normalized event itself.
    assert events[0].event_type == "PROCESS_CREATE"
    assert events[1].details["bytes_transferred"] == 88_000_000


def test_evidence_classification_integrated_into_findings():
    """Verify EvidenceClassificationEngine output is integrated into AI-generated findings."""
    event = SimpleNamespace(
        event_id="EV-001",
        event_type="PROCESS_CREATE",
        details={
            "image": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand AAAA",
        },
    )

    finding = create_finding_from_event(event)

    # Finding title is preserved from anomaly detection engine
    assert "Encoded / Malicious PowerShell Command Detected" in finding.finding_title

    # Classification fields are derived from EvidenceClassificationEngine
    assert finding.behavior_classification == "PROCESS_EXECUTION"
    assert finding.classification_confidence == 0.96
    assert "PowerShell execution indicators" in finding.classification_reason

    # Finding description integrates relevant classification context
    assert "Behavior Classification:\nPROCESS_EXECUTION" in finding.description
    assert "Classification Confidence:\n0.96" in finding.description
    assert "PowerShell execution indicators" in finding.description

    # Examiner verification gate is preserved
    assert finding.validation_status == "Pending"

    # Raw evidence data is not mutated
    assert event.event_type == "PROCESS_CREATE"
    assert event.details["image"] == "powershell.exe"
    assert event.details["command_line"] == "powershell.exe -EncodedCommand AAAA"


def test_build_finding_explanation_includes_classification():
    """Verify finding explanation includes structured classification context."""
    event = SimpleNamespace(
        event_id="EV-001",
        event_type="PROCESS_CREATE",
        details={
            "image": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand AAAA",
        },
    )

    explanation = build_finding_explanation(
        event=event,
        finding_title="Encoded / Malicious PowerShell Command Detected",
        finding_type="SUSPICIOUS_EXECUTION",
        confidence_score=0.92,
    )

    assert "Behavior Classification:\nPROCESS_EXECUTION" in explanation
    assert "Classification Confidence:\n0.96" in explanation
    assert "PowerShell execution indicators" in explanation
