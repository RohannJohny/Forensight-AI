"""
Forensight AI - Canonical Event Semantics & Controlled Mapping
Ensures consistent event nomenclature across M1 (extraction) and M2 (intelligence)
while strictly preserving forensic provenance and original event types.
"""

from typing import Dict, Any, Optional

CANONICAL_EVENT_TYPE_MAPPING: Dict[str, str] = {
    # Process semantics
    "PROCESS_EXECUTION": "PROCESS_CREATE",
    "PROCESS_CREATED": "PROCESS_CREATE",
    
    # Filesystem semantics (Strict: FILE_CREATED -> FILE_CREATE, never FILE_DROP)
    "FILE_CREATED": "FILE_CREATE",
    "FILE_MODIFIED": "FILE_MODIFY",
    "FILE_ACCESSED": "FILE_ACCESS",
    "FILE_DELETED": "FILE_DELETE",
    "FILE_DOWNLOAD": "FILE_DOWNLOAD",
    "FILE_METADATA_MODIFIED": "FILE_METADATA_MODIFY",
    
    # Registry semantics
    "REGISTRY_CHANGE": "REGISTRY_WRITE",
    "REGISTRY_MODIFIED": "REGISTRY_WRITE",
    "REGISTRY_PERSISTENCE": "REGISTRY_PERSISTENCE",
    
    # Authentication semantics
    "USER_LOGIN": "LOGON",
    "USER_LOGOUT": "LOGOUT",
    "LOGIN": "LOGON",
    "LOGOUT": "LOGOUT",
    "LOGON_SUCCESS": "LOGON",
    
    # Network semantics
    "NETWORK_CONNECTION": "NETWORK_CONNECTION",
    "DNS_QUERY": "DNS_QUERY",
    
    # Artifact semantics
    "BROWSER_VISIT": "BROWSER_VISIT",
    "USB_ACTIVITY": "USB_ACTIVITY",
    "SERVICE_ACTIVITY": "SERVICE_ACTIVITY",
    "MEMORY_ARTIFACT": "MEMORY_ARTIFACT",
}


def map_canonical_event_type(raw_event_type: str) -> str:
    """
    Maps an M1 or raw event type to the controlled canonical event type.
    If already canonical or unmapped, returns uppercase stripped event type.
    """
    cleaned = (raw_event_type or "UNKNOWN").strip().upper()
    return CANONICAL_EVENT_TYPE_MAPPING.get(cleaned, cleaned)
