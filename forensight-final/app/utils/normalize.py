from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Any

from app.constants import (
    EVENT_TYPE_PROCESS_EXECUTION,
    EVENT_TYPE_FILE_CREATED,
    EVENT_TYPE_FILE_MODIFIED,
    EVENT_TYPE_FILE_ACCESSED,
    EVENT_TYPE_FILE_DELETED,
    EVENT_TYPE_FILE_METADATA_MODIFIED,
    EVENT_TYPE_FILE_DOWNLOAD,
    EVENT_TYPE_NETWORK_CONNECTION,
    EVENT_TYPE_DNS_QUERY,
    EVENT_TYPE_USER_LOGIN,
    EVENT_TYPE_USER_LOGOUT,
    EVENT_TYPE_REGISTRY_CHANGE,
    EVENT_TYPE_USB_ACTIVITY,
    EVENT_TYPE_SERVICE_ACTIVITY,
    EVENT_TYPE_BROWSER_VISIT,
    EVENT_TYPE_AUTHENTICATION,
    EVENT_TYPE_MEMORY_ARTIFACT,
    EVENT_TYPE_UNKNOWN,
)

_WINDOWS_FILETIME_EPOCH = 116444736000000000

EVENT_TYPES = {
    "process": EVENT_TYPE_PROCESS_EXECUTION,
    "execution": EVENT_TYPE_PROCESS_EXECUTION,
    "process_execution": EVENT_TYPE_PROCESS_EXECUTION,
    "file_download": EVENT_TYPE_FILE_DOWNLOAD,
    "download": EVENT_TYPE_FILE_DOWNLOAD,
    "file_created": EVENT_TYPE_FILE_CREATED,
    "created": EVENT_TYPE_FILE_CREATED,
    "creation_time": EVENT_TYPE_FILE_CREATED,
    "file_modified": EVENT_TYPE_FILE_MODIFIED,
    "modified": EVENT_TYPE_FILE_MODIFIED,
    "content_modification_time": EVENT_TYPE_FILE_MODIFIED,
    "metadata_modification_time": EVENT_TYPE_FILE_METADATA_MODIFIED,
    "change_time": EVENT_TYPE_FILE_METADATA_MODIFIED,
    "file_deleted": EVENT_TYPE_FILE_DELETED,
    "deleted": EVENT_TYPE_FILE_DELETED,
    "file_accessed": EVENT_TYPE_FILE_ACCESSED,
    "accessed": EVENT_TYPE_FILE_ACCESSED,
    "access_time": EVENT_TYPE_FILE_ACCESSED,
    "login": EVENT_TYPE_USER_LOGIN,
    "logout": EVENT_TYPE_USER_LOGOUT,
    "browser_visit": EVENT_TYPE_BROWSER_VISIT,
    "network": EVENT_TYPE_NETWORK_CONNECTION,
    "network_connection": EVENT_TYPE_NETWORK_CONNECTION,
    "dns": EVENT_TYPE_DNS_QUERY,
    "registry": EVENT_TYPE_REGISTRY_CHANGE,
    "usb": EVENT_TYPE_USB_ACTIVITY,
    "authentication": EVENT_TYPE_AUTHENTICATION,
    "service": EVENT_TYPE_SERVICE_ACTIVITY,
    "memory": EVENT_TYPE_MEMORY_ARTIFACT,
    "memory_artifact": EVENT_TYPE_MEMORY_ARTIFACT,
}

PLACEHOLDERS = {
    "",
    "_",
    "-",
    "--",
    "n/a",
    "na",
    "n.a.",
    "unknown",
    "null",
    "none",
    "not available",
    "not_applicable",
}

INVALID_TIMESTAMP_TEXT = {
    "00/00/0000",
    "00/00/0000 00:00:00",
    "00/00/0000 --:--:--",
    "0000-00-00",
    "0000-00-00 00:00:00",
    "--:--:--",
}

HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,128}$")
VFS_PREFIX_RE = re.compile(r"^[A-Za-z0-9_]{2,}:[\\/]")


def clean(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value.lower() in PLACEHOLDERS:
            return None
        return value if value else None
    return value


def normalize_timestamp(value: Any, timezone_hint: str | None = None) -> str | None:
    """Normalize forensic timestamps without ever preserving invalid placeholders."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text or text.lower() in PLACEHOLDERS or text in INVALID_TIMESTAMP_TEXT:
            return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number <= 0:
            return None
        try:
            if number > 1e16:
                seconds = (number - _WINDOWS_FILETIME_EPOCH) / 10_000_000
            elif number > 1e12:
                seconds = number / 1_000_000  # microsecond epoch
            elif number > 1e10:
                seconds = number / 1_000  # millisecond epoch
            else:
                seconds = number  # second epoch
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None

    text = str(value).strip()
    if text.isdigit():
        return normalize_timestamp(int(text), timezone_hint)

    iso = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        dt = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None

    if dt.year < 1970:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_event_type(value: Any, action: Any = None) -> str:
    raw = clean(value) or clean(action) or "UNKNOWN"
    key = str(raw).strip().lower().replace(" ", "_").replace("-", "_")
    if key in EVENT_TYPES:
        return EVENT_TYPES[key]
    return str(raw).upper().replace(" ", "_").replace("-", "_")


def normalize_action(value: Any, event_type: Any = None, macb: Any = None) -> str | None:
    explicit = clean(value)
    if explicit:
        return str(explicit).lower().replace(" ", "_")

    raw_type = str(clean(event_type) or "").strip().lower()
    mapping = (
        ("creation", "created"),
        ("content modification", "modified"),
        ("metadata modification", "metadata_modified"),
        ("change", "changed"),
        ("access", "accessed"),
        ("download", "downloaded"),
        ("execution", "executed"),
        ("login", "logged_in"),
        ("logout", "logged_out"),
        ("connection", "connected"),
        ("visit", "visited"),
    )
    for needle, action_name in mapping:
        if needle in raw_type:
            return action_name

    if isinstance(macb, str):
        flags = macb.strip().lower()
        if "m" in flags:
            return "modified"
        if "b" in flags:
            return "changed"
        if "a" in flags:
            return "accessed"
        if "c" in flags:
            return "created"
    return None


def normalize_path(value: Any) -> str | None:
    value = clean(value)
    if value is None:
        return None
    text = str(value)
    # Strip forensic virtual filesystem prefixes (e.g. FAT:\, NTFS:\, GZIP:\, TSK:\)
    # but keep single-letter Windows drive letters like C:\ or D:\
    text = VFS_PREFIX_RE.sub("", text)
    return os.path.normpath(text)


def normalize_hash(value: Any) -> str | None:
    value = clean(value)
    if value is None:
        return None
    value = str(value).strip()
    if ":" in value and value.split(":", 1)[0].lower() in {"sha1", "sha256", "md5", "sha512"}:
        value = value.split(":", 1)[1]
    value = value.lower()
    return value if HASH_RE.match(value) else None


def normalize_ip(value: Any) -> str | None:
    value = clean(value)
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return str(value)


def normalize_port(value: Any) -> int | None:
    value = clean(value)
    if value is None:
        return None
    try:
        port = int(value)
        return port if 0 <= port <= 65535 else None
    except (TypeError, ValueError):
        return None


def deterministic_event_id(source: str | None, raw: dict[str, Any], index: int = 0) -> str:
    stable = {
        "source": source,
        "timestamp": raw.get("timestamp") or raw.get("date") or raw.get("time"),
        "event_type": raw.get("event_type") or raw.get("type") or raw.get("action"),
        "host": raw.get("host") or raw.get("hostname"),
        "user": raw.get("user") or raw.get("username"),
        "process": raw.get("process") or raw.get("process_name"),
        "path": raw.get("file_path") or raw.get("path") or raw.get("filename"),
        "artifact": raw.get("artifact") or raw.get("source_artifact") or raw.get("source"),
        "index": index,
    }
    digest = hashlib.sha256(repr(sorted(stable.items())).encode()).hexdigest()[:12].upper()
    return f"EVT-{digest}"


def normalize_raw_event(raw: dict[str, Any], source: str | None = None, index: int = 0):
    from app.schemas.event_schema import NormalizedEvent

    metadata = dict(raw.get("metadata") or {})
    known = {
        "event_id", "timestamp", "date", "time", "timezone", "event_type", "type", "source",
        "host", "hostname", "user", "username", "process", "process_name",
        "command_line", "cmdline", "source_ip", "src_ip", "destination_ip", "dest_ip",
        "source_port", "src_port", "destination_port", "dest_port", "file_path", "path", "filename",
        "file_hash", "hash", "artifact", "action", "metadata", "MACB", "macb"
    }
    for key, value in raw.items():
        if key not in known:
            metadata.setdefault("source_fields", {})[key] = value

    raw_event_type = clean(raw.get("event_type") or raw.get("type"))
    action = normalize_action(raw.get("action"), raw_event_type, raw.get("MACB") or raw.get("macb"))
    event = NormalizedEvent(
        event_id=clean(raw.get("event_id")) or deterministic_event_id(source, raw, index),
        timestamp=normalize_timestamp(raw.get("timestamp") or raw.get("date") or raw.get("time")),
        event_type=normalize_event_type(raw_event_type, action),
        source=clean(raw.get("source")) or source,
        host=clean(raw.get("host")) or clean(raw.get("hostname")),
        user=clean(raw.get("user")) or clean(raw.get("username")),
        process=clean(raw.get("process")) or clean(raw.get("process_name")),
        command_line=clean(raw.get("command_line")) or clean(raw.get("cmdline")),
        source_ip=normalize_ip(raw.get("source_ip") or raw.get("src_ip")),
        destination_ip=normalize_ip(raw.get("destination_ip") or raw.get("dest_ip")),
        source_port=normalize_port(raw.get("source_port") or raw.get("src_port")),
        destination_port=normalize_port(raw.get("destination_port") or raw.get("dest_port")),
        file_path=normalize_path(raw.get("file_path") or raw.get("path") or raw.get("filename")),
        file_hash=normalize_hash(raw.get("file_hash") or raw.get("hash")),
        artifact=clean(raw.get("artifact")),
        action=action,
        metadata=metadata,
    )
    NormalizedEvent.validate_dict(event.to_dict())
    return event
