"""Forensight AI - Evidence Classification Engine (Member 2).

Classifies already-normalized forensic events into investigative behavior
categories. This is an evidence classification layer, not a verdict engine:
classification does not by itself establish maliciousness or attribution.
"""

from __future__ import annotations

from typing import Any, Dict, List


class EvidenceClassificationEngine:
    """Deterministic, explainable multi-label classification for Event records."""

    CATEGORIES = {
        "PROCESS_EXECUTION",
        "PERSISTENCE",
        "CREDENTIAL_ACCESS",
        "NETWORK_ACTIVITY",
        "DATA_STAGING",
        "DATA_EXFILTRATION",
        "AUTHENTICATION",
        "FILE_ACTIVITY",
        "OTHER",
    }

    ARCHIVE_TOOLS = ("7z.exe", "7za.exe", "winrar.exe", "rar.exe", "tar.exe")
    ARCHIVE_EXTENSIONS = (".7z", ".zip", ".rar", ".tar", ".gz")
    STAGING_LOCATIONS = ("\\windows\\temp\\", "\\users\\", "\\appdata\\", "\\temp\\")
    CREDENTIAL_INDICATORS = (
        "lsass.exe",
        "mimikatz",
        "sekurlsa",
        "procdump",
        "sam",
        "credential dumping",
        "credential access",
    )

    @classmethod
    def classify_event(
        cls, event_type: str, details: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Return primary and secondary behavior categories for one normalized event."""
        details = details or {}
        event_type = str(event_type or "").upper()
        text = " ".join(str(value) for value in details.values()).lower()

        categories: List[str] = []
        reasons: List[str] = []
        category_confidences: Dict[str, float] = {}

        def add(category: str, confidence: float, reason: str) -> None:
            if category not in categories:
                categories.append(category)
            category_confidences[category] = max(
                category_confidences.get(category, 0.0), confidence
            )
            if reason not in reasons:
                reasons.append(reason)

        if event_type == "PROCESS_CREATE":
            image = str(
                details.get("image")
                or details.get("Image")
                or details.get("process_name")
                or ""
            ).lower()
            parent = str(
                details.get("parent_image") or details.get("ParentImage") or ""
            ).lower()
            command_line = str(
                details.get("command_line") or details.get("CommandLine") or ""
            ).lower()

            add(
                "PROCESS_EXECUTION",
                0.90,
                f"The normalized event is a process-creation event involving {image or 'an unspecified process'}.",
            )

            if "powershell" in image or "powershell" in command_line:
                if any(
                    pattern in command_line
                    for pattern in ("-enc", "-encodedcommand", "iex", "downloadstring")
                ):
                    category_confidences["PROCESS_EXECUTION"] = max(
                        category_confidences["PROCESS_EXECUTION"], 0.96
                    )
                    reasons.append(
                        "The process data contains PowerShell execution indicators associated with encoded or script-based execution."
                    )

            if any(indicator in text for indicator in cls.CREDENTIAL_INDICATORS):
                add(
                    "CREDENTIAL_ACCESS",
                    0.97,
                    "The process evidence references LSASS or a recognized credential-access indicator.",
                )

            archive_detected = any(
                tool in image or tool in command_line for tool in cls.ARCHIVE_TOOLS
            )
            archive_detected = archive_detected or any(
                ext in command_line for ext in cls.ARCHIVE_EXTENSIONS
            )
            if archive_detected:
                confidence = 0.90
                if any(location in command_line for location in cls.STAGING_LOCATIONS):
                    confidence = 0.94
                    reasons.append(
                        "The archive operation targets a user or temporary staging location."
                    )
                add(
                    "DATA_STAGING",
                    confidence,
                    "The process evidence contains an archive utility or archive-file indicator consistent with data staging.",
                )

        elif event_type in ("REGISTRY_PERSISTENCE", "REGISTRY_WRITE"):
            add(
                "PERSISTENCE",
                0.90,
                "The normalized event represents registry activity associated with persistence analysis.",
            )

        elif event_type == "FILE_DROP":
            add(
                "FILE_ACTIVITY",
                0.90,
                "The normalized event records creation or dropping of a file.",
            )

        elif event_type == "NETWORK_CONNECTION":
            add(
                "NETWORK_ACTIVITY",
                0.90,
                "The normalized event records a network connection or network-flow observation.",
            )

            bytes_value = details.get("bytes_transferred") or details.get("bytes") or 0
            try:
                transferred = int(bytes_value)
            except (TypeError, ValueError):
                transferred = 0

            if transferred > 5_000_000:
                add(
                    "DATA_EXFILTRATION",
                    0.89,
                    f"The network event records a substantial outbound transfer of {transferred} bytes; this is classified as an exfiltration indicator for further examination.",
                )

        elif event_type in (
            "LOGON",
            "LOGON_SUCCESS",
            "LOGON_FAILURE",
            "AUTHENTICATION",
        ):
            add(
                "AUTHENTICATION",
                0.88,
                "The normalized event represents authentication or logon activity.",
            )

        if not categories:
            add(
                "OTHER",
                0.50,
                f"No specific M2 behavior category is currently configured for event type {event_type or 'UNKNOWN'}.",
            )

        primary = max(
            categories,
            key=lambda category: category_confidences.get(category, 0.0),
        )

        return {
            "primary_category": primary,
            "categories": categories,
            "confidence": round(category_confidences[primary], 2),
            "category_confidences": {
                category: round(score, 2)
                for category, score in category_confidences.items()
            },
            "reasons": reasons,
        }
