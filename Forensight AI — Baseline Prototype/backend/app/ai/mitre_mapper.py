"""
Forensight AI - MITRE ATT&CK Mapping Engine (Module 5)
Organizes correlated forensic findings into standard attack-path kill chain stages.
"""

from typing import Dict, Any, Optional, Tuple


class MitreAttackMapper:
    """Classifies forensic evidence into MITRE ATT&CK Tactics and Techniques."""

    TACTIC_STAGES = [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Lateral Movement",
        "Exfiltration"
    ]

    TECHNIQUE_RULES = [
        # Initial Access
        {
            "stage": "Initial Access",
            "order": 1,
            "technique": "T1566: Phishing (Spearphishing Attachment)",
            "keywords": ["phishing", "spearphish", "invoice.docm", "outlook.exe", "winword.exe", "email attachment"]
        },
        # Execution
        {
            "stage": "Execution",
            "order": 2,
            "technique": "T1059.001: Command and Scripting Interpreter (PowerShell)",
            "keywords": ["powershell", "-enc", "bypass", "cmd.exe", "wscript", "script interpreter"]
        },
        # Persistence
        {
            "stage": "Persistence",
            "order": 3,
            "technique": "T1547.001: Boot or Logon Autostart Execution (Registry Run Keys)",
            "keywords": ["run", "runonce", "registry_persistence", "autostart", "schtasks"]
        },
        # Privilege Escalation
        {
            "stage": "Privilege Escalation",
            "order": 4,
            "technique": "T1068 / T1003: Exploitation / OS Credential Dumping (LSASS)",
            "keywords": ["lsass", "mimikatz", "sekurlsa", "privilege escalation", "whoami /priv", "seebugprivilege"]
        },
        # Lateral Movement
        {
            "stage": "Lateral Movement",
            "order": 5,
            "technique": "T1021.002: Remote Services (SMB / Windows Admin Shares)",
            "keywords": ["smb", "445", "psexec", "lateral movement", "192.168.1.150", "admin$"]
        },
        # Exfiltration
        {
            "stage": "Exfiltration",
            "order": 6,
            "technique": "T1048: Exfiltration Over Alternative Protocol / Cloud Channel",
            "keywords": ["exfiltration", "data_exfiltration", "megaupload", "transfer.sh", "upload", "outbound data transfer"]
        }
    ]

    @classmethod
    def map_finding_to_stage(cls, title: str, description: str, finding_type: str) -> Tuple[str, int, str]:
        """
        Maps a finding title/description/type to (stage_name, stage_order, mitre_technique).
        """
        search_blob = f"{title} {description} {finding_type}".lower()

        for rule in cls.TECHNIQUE_RULES:
            for kw in rule["keywords"]:
                if kw in search_blob:
                    return rule["stage"], rule["order"], rule["technique"]

        # Default fallback stage based on finding_type
        if "EXECUTION" in finding_type:
            return "Execution", 2, "T1059: Command and Scripting"
        elif "PERSISTENCE" in finding_type:
            return "Persistence", 3, "T1547: Persistence Mechanism"
        elif "CREDENTIAL" in finding_type:
            return "Privilege Escalation", 4, "T1003: Credential Access"
        elif "EXFILTRATION" in finding_type:
            return "Exfiltration", 6, "T1048: Exfiltration"

        return "Execution", 2, "T1204: User Execution"
