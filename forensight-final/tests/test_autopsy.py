from __future__ import annotations

import sqlite3
from pathlib import Path
from app.extractors.autopsy_reports import parse_autopsy_output
from app.pipeline import normalize_events


def test_autopsy_sqlite_extractor(tmp_path: Path):
    case_dir = tmp_path / "case_01"
    case_dir.mkdir()
    db_path = case_dir / "autopsy.db"

    conn = sqlite3.connect(str(db_path))
    conn.execute("""
    CREATE TABLE tsk_event_types (event_type_id INTEGER PRIMARY KEY, display_name TEXT);
    """)
    conn.execute("""
    CREATE TABLE tsk_event_descriptions (event_description_id INTEGER PRIMARY KEY, full_description TEXT);
    """)
    conn.execute("""
    CREATE TABLE tsk_events (event_id INTEGER PRIMARY KEY, event_type_id INTEGER, event_description_id INTEGER, time INTEGER);
    """)
    conn.execute("""
    CREATE TABLE blackboard_artifact_types (artifact_type_id INTEGER PRIMARY KEY, type_name TEXT, display_name TEXT);
    """)
    conn.execute("""
    CREATE TABLE blackboard_attribute_types (attribute_type_id INTEGER PRIMARY KEY, type_name TEXT, display_name TEXT);
    """)
    conn.execute("""
    CREATE TABLE blackboard_artifacts (artifact_id INTEGER PRIMARY KEY, artifact_type_id INTEGER);
    """)
    conn.execute("""
    CREATE TABLE blackboard_attributes (
        artifact_id INTEGER, artifact_type_id INTEGER, source TEXT, attribute_type_id INTEGER,
        value_text TEXT, value_int32 INTEGER, value_int64 INTEGER, value_double REAL
    );
    """)
    conn.execute("""
    CREATE TABLE tsk_files (
        obj_id INTEGER PRIMARY KEY, name TEXT, parent_path TEXT, size INTEGER,
        dir_type INTEGER, meta_type INTEGER, crtime INTEGER, mtime INTEGER, atime INTEGER, ctime INTEGER,
        md5 TEXT, sha256 TEXT
    );
    """)

    # Populate mock test data
    conn.execute("INSERT INTO tsk_event_types VALUES (1, 'File Created')")
    conn.execute("INSERT INTO tsk_event_descriptions VALUES (1, '/Windows/System32/calc.exe')")
    conn.execute("INSERT INTO tsk_events VALUES (1, 1, 1, 1600000000)")

    conn.execute("INSERT INTO blackboard_artifact_types VALUES (1, 'TSK_WEB_BOOKMARK', 'Web Bookmark')")
    conn.execute("INSERT INTO blackboard_attribute_types VALUES (1, 'TSK_URL', 'URL')")
    conn.execute("INSERT INTO blackboard_artifacts VALUES (100, 1)")
    conn.execute("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, attribute_type_id, value_text) VALUES (100, 1, 'Chrome', 1, 'https://example.com')")

    conn.execute("INSERT INTO tsk_files VALUES (10, 'evil.exe', '/Users/Admin/Downloads', 1024, 5, 1, 1600000000, 1600000100, 1600000200, 1600000300, 'd41d8cd98f00b204e9800998ecf8427e', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')")
    conn.commit()
    conn.close()

    events = parse_autopsy_output(case_dir)
    assert len(events) >= 3

    norm = normalize_events(events, source="Autopsy")
    assert len(norm) >= 3

    event_types = set(e.event_type for e in norm)
    assert "FILE_CREATED" in event_types or "FILE_MODIFIED" in event_types
