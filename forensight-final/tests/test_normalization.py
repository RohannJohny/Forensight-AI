from app.extractors.json_extractor import extract_json
from app.pipeline import normalize_events, deduplicate
from app.schemas.event_schema import TOP_LEVEL_FIELDS
from app.utils.normalize import normalize_timestamp


def test_schema_exact():
    raw = extract_json("sample_data/synthetic_forensic_events.json")
    events = normalize_events(raw, "JSON")
    assert events
    for event in events:
        data = event.to_dict()
        assert tuple(data.keys()) == TOP_LEVEL_FIELDS
        assert isinstance(data["metadata"], dict)


def test_timestamp_normalized_to_utc():
    assert normalize_timestamp("2026-10-05T10:00:00+05:30") == "2026-10-05T04:30:00Z"


def test_duplicate_event_ids_removed():
    raw = extract_json("sample_data/synthetic_forensic_events.json")
    a = normalize_events(raw[:1], "JSON")[0]
    b = normalize_events(raw[:1], "JSON")[0]
    assert len(deduplicate([a, b])) == 1


def test_network_fields_are_typed():
    raw = extract_json("sample_data/synthetic_forensic_events.json")
    event = normalize_events([raw[-1]], "JSON")[0].to_dict()
    assert event["source_port"] == 52144
    assert event["destination_port"] == 443
    assert event["destination_ip"] == "203.0.113.50"


def test_placeholders_become_none():
    from app.utils.normalize import normalize_raw_event
    event = normalize_raw_event({
        "timestamp": "00/00/0000",
        "event_type": "Content Modification Time",
        "host": "_",
        "user": "-",
        "file_path": "GZIP:\\foo\\bar",
        "source": "FILE",
        "MACB": "M",
    }, "Plaso", 0).to_dict()
    assert event["timestamp"] is None
    assert event["host"] is None
    assert event["user"] is None
    assert event["event_type"] == "FILE_MODIFIED"
    assert event["action"] == "modified"
    assert event["file_path"].endswith("foo\\bar")
