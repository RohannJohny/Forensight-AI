from __future__ import annotations

import csv
import glob
import json
import sqlite3
from pathlib import Path
from typing import Any


def _walk_json(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        keys = {str(k).lower() for k in value}
        if keys & {"timestamp", "event_type", "type", "artifact", "description", "source"}:
            found.append(value)
        for child in value.values():
            found.extend(_walk_json(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_json(child))
    return found


def _parse_autopsy_sqlite_db(db_path: Path) -> list[dict[str, Any]]:
    """Extracts forensic events from Autopsy's SQLite case database (autopsy.db)."""
    events: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except Exception:
        try:
            conn = sqlite3.connect(str(db_path))
        except Exception:
            return events

    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 1. Extract timeline events from tsk_events
    try:
        query_events = """
        SELECT e.event_id, e.time, t.display_name AS event_type, d.full_description AS description
        FROM tsk_events e
        LEFT JOIN tsk_event_types t ON e.event_type_id = t.event_type_id
        LEFT JOIN tsk_event_descriptions d ON e.event_description_id = d.event_description_id
        WHERE e.time IS NOT NULL AND e.time > 0
        """
        for row in cur.execute(query_events).fetchall():
            time_val = row["time"]
            desc = row["description"] or ""
            ev_type = row["event_type"] or "FILE_ACTIVITY"
            events.append({
                "timestamp": time_val,
                "event_type": ev_type,
                "source": "Autopsy Timeline",
                "file_path": desc if "/" in desc or "\\" in desc else None,
                "artifact": "TSK Timeline",
                "action": "timeline_recorded",
                "metadata": {
                    "autopsy_event_id": row["event_id"],
                    "description": desc,
                    "db_path": str(db_path),
                },
            })
    except Exception:
        pass

    # 2. Extract blackboard artifacts (web history, USB, installed apps, recent files, etc.)
    try:
        query_artifacts = """
        SELECT
            a.artifact_id,
            at.type_name AS artifact_type,
            at.display_name AS artifact_display_name,
            att.type_name AS attribute_type,
            att.display_name AS attribute_display_name,
            b.source,
            b.value_text,
            b.value_int32,
            b.value_int64,
            b.value_double
        FROM blackboard_artifacts a
        JOIN blackboard_artifact_types at ON a.artifact_type_id = at.artifact_type_id
        JOIN blackboard_attributes b ON a.artifact_id = b.artifact_id
        JOIN blackboard_attribute_types att ON b.attribute_type_id = att.attribute_type_id
        """
        artifact_groups: dict[int, dict[str, Any]] = {}
        for row in cur.execute(query_artifacts).fetchall():
            aid = row["artifact_id"]
            if aid not in artifact_groups:
                artifact_groups[aid] = {
                    "artifact_type": row["artifact_display_name"] or row["artifact_type"],
                    "source": row["source"] or "Autopsy Ingest",
                    "attributes": {},
                }
            val = row["value_text"] or row["value_int64"] or row["value_int32"] or row["value_double"]
            attr_key = row["attribute_display_name"] or row["attribute_type"]
            artifact_groups[aid]["attributes"][attr_key] = val

        for aid, art in artifact_groups.items():
            attrs = art["attributes"]
            # Look for common forensic attributes
            dt = attrs.get("Date Created") or attrs.get("Date/Time") or attrs.get("Date Accessed")
            url = attrs.get("URL")
            prog = attrs.get("Program Name")
            path = attrs.get("Path") or attrs.get("File Name")

            events.append({
                "timestamp": dt,
                "event_type": "ARTIFACT_DETECTED",
                "source": "Autopsy Blackboard",
                "process": prog,
                "file_path": path,
                "artifact": art["artifact_type"],
                "action": "extracted",
                "metadata": {
                    "artifact_id": aid,
                    "attributes": attrs,
                    "url": url,
                },
            })
    except Exception:
        pass

    # 3. Extract file entries from tsk_files with valid hashes or timestamps
    try:
        query_files = """
        SELECT obj_id, name, parent_path, size, crtime, mtime, atime, ctime, md5, sha256
        FROM tsk_files
        WHERE (dir_type = 5 OR meta_type = 1) AND (crtime > 0 OR mtime > 0 OR md5 IS NOT NULL OR sha256 IS NOT NULL)
        LIMIT 5000
        """
        for row in cur.execute(query_files).fetchall():
            fname = row["name"]
            if fname in (".", "..", "$Unalloc") or fname.startswith("Unalloc_"):
                continue
            parent = row["parent_path"] or ""
            full_path = (parent.rstrip("/") + "/" + fname) if parent else fname

            if row["mtime"] and row["mtime"] > 0:
                events.append({
                    "timestamp": row["mtime"],
                    "event_type": "FILE_MODIFIED",
                    "source": "Autopsy Filesystem",
                    "file_path": full_path,
                    "file_hash": row["sha256"] or row["md5"],
                    "artifact": "TSK File Record",
                    "action": "modified",
                    "metadata": {
                        "size": row["size"],
                        "crtime": row["crtime"],
                        "atime": row["atime"],
                        "ctime": row["ctime"],
                    },
                })
    except Exception:
        pass

    conn.close()
    return events


def parse_autopsy_output(directory: str | Path) -> list[dict[str, Any]]:
    """Harvests records from Autopsy's SQLite database (autopsy.db) as well as any CSV/JSON reports."""
    root = Path(directory).resolve()
    events: list[dict[str, Any]] = []

    # 1. Scan for autopsy.db SQLite database
    db_candidates = list(root.rglob("autopsy.db"))
    for db_path in db_candidates:
        events.extend(_parse_autopsy_sqlite_db(db_path))

    # 2. Scan for any exported JSON reports
    for path in sorted(root.rglob("*.json")):
        if path.name in ("command.json", "status.json"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for row in _walk_json(data):
            row = dict(row)
            row.setdefault("source", "Autopsy")
            row.setdefault("artifact", path.name)
            row.setdefault("metadata", {})
            row["metadata"] = {**row.get("metadata", {}), "autopsy_file": str(path.relative_to(root))}
            events.append(row)

    # 3. Scan for any exported CSV reports
    for path in sorted(root.rglob("*.csv")):
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                for row in csv.DictReader(handle):
                    row = dict(row)
                    row.setdefault("source", "Autopsy")
                    row.setdefault("artifact", path.name)
                    row["metadata"] = {"autopsy_file": str(path.relative_to(root))}
                    events.append(row)
        except Exception:
            continue

    return events
