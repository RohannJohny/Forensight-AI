from app.extractors.plaso_extractor import extract_plaso_csv
from app.utils.normalize import normalize_event_type, normalize_timestamp, normalize_raw_event


def test_invalid_placeholder_timestamp_becomes_none(tmp_path):
    csv_path = tmp_path / "timeline.csv"
    csv_path.write_text(
        "date,time,timezone,MACB,source,sourcetype,type,user,host,filename\n"
        "00/00/0000,--:--:--,-,M,FILE,File stat,Content Modification Time,-,-,GZIP:\\\\.fsevents\\\\0001\n",
        encoding="utf-8",
    )
    events = extract_plaso_csv(csv_path)
    normalized = normalize_raw_event(events[0], source="Plaso", index=0).to_dict()
    assert normalized["timestamp"] is None
    assert normalized["user"] is None
    assert normalized["host"] is None


def test_valid_plaso_date_and_time_are_combined(tmp_path):
    csv_path = tmp_path / "timeline.csv"
    csv_path.write_text(
        "date,time,timezone,MACB,source,sourcetype,type,user,host,filename\n"
        "10/05/2026,10:32:41,UTC,M,FILE,File stat,Content Modification Time,john,HOST01,C:\\\\Users\\\\john\\\\a.txt\n",
        encoding="utf-8",
    )
    events = extract_plaso_csv(csv_path)
    normalized = normalize_raw_event(events[0], source="Plaso", index=0).to_dict()
    assert normalized["timestamp"] == "2026-10-05T10:32:41Z"
    assert normalized["event_type"] == "FILE_MODIFIED"
    assert normalized["action"] == "modified"
    assert normalized["artifact"] == "FILE (File stat)"
    assert normalized["file_path"].endswith("a.txt")


def test_unparseable_timestamp_becomes_none():
    assert normalize_timestamp("not-a-date") is None


def test_plaso_type_mapping():
    assert normalize_event_type("Creation Time") == "FILE_CREATED"
    assert normalize_event_type("Content Modification Time") == "FILE_MODIFIED"
    assert normalize_event_type("Access Time") == "FILE_ACCESSED"


def test_screenshot_like_plaso_fields_normalize_cleanly(tmp_path):
    csv_path = tmp_path / "plaso_like.csv"
    csv_path.write_text(
        "date,time,timezone,MACB,source,sourcetype,type,user,host,filename\n"
        "00/00/0000,--:--:--,-,M,FILE,File stat,Content Modification Time,-,-,GZIP:\\\\.fsevents\\\\0001\n",
        encoding="utf-8",
    )
    events = extract_plaso_csv(csv_path)
    normalized = normalize_raw_event(events[0], source="Plaso", index=0).to_dict()
    assert normalized["timestamp"] is None
    assert normalized["source"] == "FILE"
    assert normalized["event_type"] == "FILE_MODIFIED"
    assert normalized["action"] == "modified"
    assert normalized["artifact"] == "FILE (File stat)"
