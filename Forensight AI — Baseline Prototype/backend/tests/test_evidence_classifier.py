from types import SimpleNamespace

from app.ai.evidence_classifier import EvidenceClassificationEngine


def test_blackout_event_classification():
    events = [
        ("PROCESS_CREATE", {"image": "WINWORD.EXE"}, "PROCESS_EXECUTION"),
        (
            "PROCESS_CREATE",
            {"image": "powershell.exe", "command_line": "powershell.exe -Enc AAA"},
            "PROCESS_EXECUTION",
        ),
        ("FILE_DROP", {"target_filename": "C:\\Temp\\svchost32.exe"}, "FILE_ACTIVITY"),
        (
            "REGISTRY_PERSISTENCE",
            {"key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            "PERSISTENCE",
        ),
        (
            "PROCESS_CREATE",
            {
                "image": "svchost32.exe",
                "target_accessed": "C:\\Windows\\System32\\lsass.exe",
            },
            "CREDENTIAL_ACCESS",
        ),
        (
            "NETWORK_CONNECTION",
            {"dst_ip": "192.168.1.150", "dst_port": 445},
            "NETWORK_ACTIVITY",
        ),
        (
            "PROCESS_CREATE",
            {
                "image": "cmd.exe",
                "command_line": "7z.exe a -p[REDACTED] C:\\Windows\\Temp\\data.7z",
                "target_archive": "C:\\Windows\\Temp\\data.7z",
            },
            "DATA_STAGING",
        ),
        (
            "NETWORK_CONNECTION",
            {"dst_port": 443, "protocol": "HTTPS", "bytes_transferred": 88604672},
            "DATA_EXFILTRATION",
        ),
    ]

    for event_type, details, expected_primary in events:
        result = EvidenceClassificationEngine.classify_event(event_type, details)
        assert expected_primary in result["categories"], result
        assert result["confidence"] >= 0.50


def test_large_network_transfer_is_multilabel():
    result = EvidenceClassificationEngine.classify_event(
        "NETWORK_CONNECTION",
        {"protocol": "HTTPS", "bytes_transferred": 88_604_672},
    )
    assert result["primary_category"] == "NETWORK_ACTIVITY"
    assert "NETWORK_ACTIVITY" in result["categories"]
    assert "DATA_EXFILTRATION" in result["categories"]


def test_unknown_event_is_safe():
    result = EvidenceClassificationEngine.classify_event("UNKNOWN_EVENT", {})
    assert result["primary_category"] == "OTHER"
    assert result["confidence"] == 0.50
