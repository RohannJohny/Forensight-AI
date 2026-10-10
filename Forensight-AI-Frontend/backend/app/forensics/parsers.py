"""
Forensight AI - Forensic Extraction & Normalization Engine (Module 2)
Parses heterogeneous forensic data sources and converts them into the
Common Event Model (CEM) with standardized UTC timestamps and entities.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional


class CommonEventModel:
    """Standardized forensic event schema."""
    @staticmethod
    def normalize(
        timestamp: datetime,
        event_type: str,
        source_entity: str,
        user_account: Optional[str] = None,
        host_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return {
            "timestamp": timestamp,
            "event_type": event_type.upper(),
            "source_entity": source_entity,
            "user_account": user_account or "SYSTEM",
            "host_ip": host_ip or "127.0.0.1",
            "details": details or {}
        }


class WindowsEventLogParser:
    """Parses Security and System Event log structures (EVTX/JSON representation)."""
    @staticmethod
    def parse_record(record: Dict[str, Any], source_file: str = "Security.evtx") -> Dict[str, Any]:
        event_id = str(record.get("event_id", "0"))
        time_str = record.get("timestamp")
        if isinstance(time_str, str):
            ts = datetime.fromisoformat(time_str.replace("Z", "+00:00")).replace(tzinfo=None)
        else:
            ts = time_str or datetime.utcnow()

        user = record.get("user") or record.get("TargetUserName") or "SYSTEM"
        ip = record.get("ip") or record.get("IpAddress") or "127.0.0.1"

        if event_id == "4624":
            etype = "LOGON_SUCCESS"
        elif event_id == "4625":
            etype = "LOGON_FAILURE"
        elif event_id == "4688":
            etype = "PROCESS_CREATE"
        elif event_id == "7045":
            etype = "SERVICE_INSTALL"
        else:
            etype = f"EVENT_LOG_{event_id}"

        return CommonEventModel.normalize(
            timestamp=ts,
            event_type=etype,
            source_entity=source_file,
            user_account=user,
            host_ip=ip,
            details=record
        )


class SysmonLogParser:
    """Parses Sysmon operational events (Process creation, network connections, file drops)."""
    @staticmethod
    def parse_record(record: Dict[str, Any], source_file: str = "Microsoft-Windows-Sysmon.evtx") -> Dict[str, Any]:
        event_id = str(record.get("event_id", "1"))
        time_str = record.get("timestamp")
        if isinstance(time_str, str):
            ts = datetime.fromisoformat(time_str.replace("Z", "+00:00")).replace(tzinfo=None)
        else:
            ts = time_str or datetime.utcnow()

        user = record.get("User") or record.get("user") or "SYSTEM"
        host = record.get("Host") or record.get("host_ip") or "192.168.1.105"

        if event_id == "1":
            etype = "PROCESS_CREATE"
        elif event_id == "3":
            etype = "NETWORK_CONNECTION"
        elif event_id == "11":
            etype = "FILE_DROP"
        elif event_id == "13":
            etype = "REGISTRY_WRITE"
        else:
            etype = f"SYSMON_{event_id}"

        return CommonEventModel.normalize(
            timestamp=ts,
            event_type=etype,
            source_entity=source_file,
            user_account=user,
            host_ip=host,
            details=record
        )


class RegistryParser:
    """Parses Registry hive dumps (Persistence keys, UserAssist, Run keys)."""
    @staticmethod
    def parse_entry(entry: Dict[str, Any], source_file: str = "NTUSER.DAT") -> Dict[str, Any]:
        time_str = entry.get("timestamp")
        if isinstance(time_str, str):
            ts = datetime.fromisoformat(time_str.replace("Z", "+00:00")).replace(tzinfo=None)
        else:
            ts = time_str or datetime.utcnow()

        return CommonEventModel.normalize(
            timestamp=ts,
            event_type="REGISTRY_PERSISTENCE",
            source_entity=source_file,
            user_account=entry.get("user", "LocalUser"),
            host_ip=entry.get("host_ip", "192.168.1.105"),
            details={
                "hive": entry.get("hive", "HKLM"),
                "key_path": entry.get("key_path"),
                "value_name": entry.get("value_name"),
                "value_data": entry.get("value_data")
            }
        )


class NetworkFlowParser:
    """Parses PCAP / Zeek network flow records."""
    @staticmethod
    def parse_flow(flow: Dict[str, Any], source_file: str = "capture.pcap") -> Dict[str, Any]:
        time_str = flow.get("timestamp")
        if isinstance(time_str, str):
            ts = datetime.fromisoformat(time_str.replace("Z", "+00:00")).replace(tzinfo=None)
        else:
            ts = flow.get("timestamp") or datetime.utcnow()

        return CommonEventModel.normalize(
            timestamp=ts,
            event_type="NETWORK_CONNECTION",
            source_entity=source_file,
            user_account=flow.get("user", "NETWORK_SERVICE"),
            host_ip=flow.get("src_ip", "192.168.1.105"),
            details={
                "src_ip": flow.get("src_ip"),
                "src_port": flow.get("src_port"),
                "dst_ip": flow.get("dst_ip"),
                "dst_port": flow.get("dst_port"),
                "protocol": flow.get("protocol", "TCP"),
                "bytes_transferred": flow.get("bytes", 0),
                "domain": flow.get("domain", "")
            }
        )
