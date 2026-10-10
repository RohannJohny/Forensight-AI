import re
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Case, Finding, Event, AuditLog, Artifact, Evidence, AttackNode
from app.schemas.schemas import FindingResponse, FindingCreate, FindingUpdate
from app.ai.anomaly_engine import AnomalyDetectionEngine
from app.ai.evidence_classifier import EvidenceClassificationEngine
from app.ai.mitre_mapper import MitreAttackMapper


router = APIRouter(tags=["Findings & Examiner Validation Gate (Module 5 & 6)"])


def classify_events_for_m2(events):
    """Classify normalized events for the M2 analysis pipeline.

    Returns response-ready classification metadata without modifying the
    Event records or changing anomaly/correlation behavior.
    """
    event_classifications = {}
    classification_summary = {}

    for ev in events:
        classification = EvidenceClassificationEngine.classify_event(
            ev.event_type,
            ev.details or {},
        )

        event_classifications[ev.event_id] = {
            "event_id": ev.event_id,
            "event_type": ev.event_type,
            **classification,
        }

        for category in classification["categories"]:
            classification_summary[category] = (
                classification_summary.get(category, 0) + 1
            )

    return event_classifications, classification_summary


def build_confidence_factors(
    event,
    finding_type: str,
) -> str:
    """
    Describe the normalized evidence factors supporting an AI finding.

    This is an explainability layer, not a probability calculation.
    It does not alter the anomaly score.
    """

    details = event.details if isinstance(event.details, dict) else {}

    image = (
        details.get("image")
        or details.get("Image")
        or details.get("process_name")
        or ""
    )

    parent_image = details.get("parent_image") or details.get("ParentImage") or ""

    command_line = details.get("command_line") or details.get("CommandLine") or ""

    key_path = details.get("key_path") or details.get("TargetObject") or ""

    target_accessed = details.get("target_accessed", "")

    target_archive = details.get("target_archive", "")

    bytes_transferred = details.get("bytes_transferred") or details.get("bytes") or 0

    dst_port = details.get("dst_port") or details.get("DestinationPort") or ""

    factors = []

    # Suspicious process execution
    if finding_type == "SUSPICIOUS_EXECUTION":
        if parent_image:
            factors.append(f"Parent process present: {parent_image}")

        if image:
            factors.append(f"Process image identified: {image}")

        if command_line:
            factors.append(
                "Command-line execution characteristics matched "
                "a suspicious execution rule."
            )

    # Credential access
    elif finding_type == "CREDENTIAL_ACCESS":
        if target_accessed:
            factors.append(f"Credential-sensitive target accessed: {target_accessed}")

        if image:
            factors.append(f"Process involved: {image}")

        factors.append("Behavior matched a credential-access detection indicator.")

    # Persistence
    elif finding_type == "PERSISTENCE":
        if key_path:
            factors.append(f"Persistence registry key: {key_path}")

        factors.append("Registry location matched a known persistence pattern.")

    # Data staging
    elif finding_type == "DATA_STAGING":
        if image:
            factors.append(f"Process involved: {image}")

        if target_archive:
            factors.append(f"Archive target identified: {target_archive}")

        if command_line:
            factors.append(
                "Archive utility or archive extension detected in the command line."
            )

        factors.append("Archive activity occurred in a staging location.")

    # Data exfiltration
    elif finding_type == "DATA_EXFILTRATION":
        if bytes_transferred:
            factors.append(f"Outbound transfer volume: {bytes_transferred} bytes")

        if dst_port:
            factors.append(f"Destination port: {dst_port}")

        factors.append(
            "Outbound transfer volume exceeded the configured anomaly threshold."
        )

    # Command and control
    elif finding_type == "COMMAND_AND_CONTROL":
        if dst_port:
            factors.append(f"Non-standard destination port detected: {dst_port}")

        factors.append("Network activity matched a configured C2 detection indicator.")

    # Authentication anomaly
    elif finding_type == "AUTHENTICATION_ANOMALY":
        factors.append(
            "Authentication failure matched the configured anomaly detection threshold."
        )

    if not factors:
        factors.append("The event matched a configured behavioral detection rule.")

    return "\n".join(f"- {factor}" for factor in factors)


def build_finding_explanation(
    event,
    finding_title: str,
    finding_type: str,
    confidence_score: float,
    classification: Dict[str, Any] | None = None,
) -> str:
    """
    Build an evidence-grounded explanation for an AI-generated finding.

    The explanation is generated only from normalized event fields and
    integrated evidence classification context.
    It explains:
    1. What happened
    2. Why the behavior is suspicious
    3. Which evidence fields triggered the detection
    4. Detection confidence
    5. What the examiner should verify
    """

    if classification is None and hasattr(event, "event_type"):
        ev_details = (
            getattr(event, "details", {})
            if isinstance(getattr(event, "details", None), dict)
            else {}
        )
        classification = EvidenceClassificationEngine.classify_event(
            event.event_type, ev_details
        )

    details = event.details if isinstance(event.details, dict) else {}

    # Process-related evidence
    image = (
        details.get("image")
        or details.get("Image")
        or details.get("process_name")
        or ""
    )

    parent_image = details.get("parent_image") or details.get("ParentImage") or ""

    command_line = details.get("command_line") or details.get("CommandLine") or ""

    # Registry-related evidence
    key_path = details.get("key_path") or details.get("TargetObject") or ""

    value_data = details.get("value_data") or details.get("Details") or ""

    # Credential-access evidence
    target_accessed = details.get("target_accessed", "")

    # Archive/data-staging evidence
    target_archive = details.get("target_archive", "")

    # Network evidence
    dst_ip = details.get("dst_ip") or details.get("DestinationIp") or ""

    bytes_transferred = details.get("bytes_transferred") or details.get("bytes") or 0

    # ---------------------------------------------------------
    # Build evidence trigger from available normalized fields
    # ---------------------------------------------------------

    evidence_parts = []

    if image:
        evidence_parts.append(f"process={image}")

    if parent_image:
        evidence_parts.append(f"parent_process={parent_image}")

    if command_line:
        safe_command_line = command_line

        # Redact password-like values commonly used in archive commands.
        safe_command_line = re.sub(
            r"(?i)(-p)([^\s\"']+)",
            r"\1[REDACTED]",
            safe_command_line,
        )

    evidence_parts.append(f"command_line={safe_command_line}")

    if key_path:
        evidence_parts.append(f"registry_key={key_path}")

    if value_data:
        evidence_parts.append(f"value_data={value_data}")

    if target_accessed:
        evidence_parts.append(f"target_accessed={target_accessed}")

    if target_archive:
        evidence_parts.append(f"target_archive={target_archive}")

    if dst_ip:
        evidence_parts.append(f"destination={dst_ip}")

    if bytes_transferred:
        evidence_parts.append(f"bytes_transferred={bytes_transferred}")

    evidence_text = (
        "; ".join(evidence_parts)
        if evidence_parts
        else "No specific normalized evidence field was available."
    )

    # ---------------------------------------------------------
    # Finding-type-specific explanation
    # ---------------------------------------------------------

    if finding_type == "SUSPICIOUS_EXECUTION":
        explanation = (
            "A process execution matched a suspicious execution pattern. "
            "The process relationship or command-line characteristics "
            "indicate behavior that requires forensic review."
        )

        verification = (
            "Verify the process image, parent process, command line, "
            "execution timestamp, and originating evidence artifact."
        )

    elif finding_type == "CREDENTIAL_ACCESS":
        explanation = (
            "A process exhibited behavior associated with credential access. "
            "Access to credential-sensitive targets such as LSASS or the use "
            "of credential-dumping tooling can indicate an attempt to obtain "
            "authentication material."
        )

        verification = (
            "Verify the process identity, parent process, accessed target, "
            "process IDs, command line, and associated memory or event-log evidence."
        )

    elif finding_type == "PERSISTENCE":
        explanation = (
            "A registry modification established a persistence mechanism. "
            "The registry location and stored executable or command indicate "
            "that the process may be configured to execute automatically."
        )

        verification = (
            "Verify the registry key, value data, creation or modification "
            "time, referenced executable, and corresponding registry artifact."
        )

    elif finding_type == "DATA_STAGING":
        explanation = (
            "An archive or staging operation was detected. Archive utilities "
            "or archive files created in user or temporary locations can indicate "
            "preparation of collected data for subsequent transfer."
        )

        verification = (
            "Verify the archive file, its contents, creation process, timestamps, "
            "source files, and any subsequent network activity."
        )

    elif finding_type == "DATA_EXFILTRATION":
        explanation = (
            "A substantial outbound data transfer was detected. The transfer "
            "volume and destination provide evidence that data may have been "
            "sent outside the host."
        )

        verification = (
            "Verify the destination, protocol, transferred byte count, network "
            "flow records, related process activity, and available packet evidence."
        )

    elif finding_type == "COMMAND_AND_CONTROL":
        explanation = (
            "Network activity matched a suspicious command-and-control pattern, "
            "including communication over a non-standard destination port."
        )

        verification = (
            "Verify the destination IP, destination port, protocol, process "
            "responsible for the connection, and surrounding network events."
        )

    elif finding_type == "AUTHENTICATION_ANOMALY":
        explanation = (
            "A failed authentication event was detected and classified as "
            "potentially anomalous. Repeated or contextually unusual failures "
            "may indicate attempted unauthorized access."
        )

        verification = (
            "Verify the account, source host, timestamp, number of related "
            "authentication failures, and surrounding logon activity."
        )

    else:
        explanation = (
            "The event matched a behavioral detection rule and was classified "
            "as potentially suspicious."
        )

        verification = (
            "Verify the original evidence artifact and the normalized event "
            "fields supporting this classification."
        )

    # ---------------------------------------------------------
    # Final evidence-grounded finding description
    # ---------------------------------------------------------

    confidence_factors = build_confidence_factors(
        event=event,
        finding_type=finding_type,
    )

    classification_block = ""
    if classification and classification.get("primary_category"):
        primary = classification.get("primary_category")
        conf = classification.get("confidence")
        reasons_list = classification.get("reasons", [])
        reason_text = reasons_list[-1] if reasons_list else ""
        classification_block = (
            f"Behavior Classification:\n{primary}\n\n"
            f"Classification Confidence:\n{conf}\n\n"
            f"Classification Reason:\n{reason_text}\n\n"
        )

    title_block = f"Finding:\n{finding_title}\n\n" if finding_title else ""

    return (
        f"{title_block}"
        f"{classification_block}"
        f"{explanation}\n\n"
        f"Evidence trigger: {evidence_text}\n\n"
        f"Detection confidence: {confidence_score * 100:.0f}%.\n\n"
        f"Confidence factors:\n"
        f"{confidence_factors}\n\n"
        f"Examiner verification: {verification}"
    )


def create_finding_from_event(
    event,
    case_id: str = "CASE-DEFAULT",
    finding_title: str | None = None,
    finding_type: str | None = None,
    confidence_score: float | None = None,
    classification: Dict[str, Any] | None = None,
    validation_status: str = "Pending",
    investigator_notes: str = "Generated by Anomaly Engine; awaiting examiner review.",
) -> Finding:
    """Helper to generate an AI finding grounded in normalized evidence and classification."""
    details = getattr(event, "details", {}) or {}
    event_type = getattr(event, "event_type", "")

    if finding_title is None or finding_type is None or confidence_score is None:
        is_anom, score, title, ftype = AnomalyDetectionEngine.evaluate_event(
            event_type, details
        )
        finding_title = finding_title or title or "Anomalous Behavioral Event Detected"
        finding_type = finding_type or ftype or "SUSPICIOUS_BEHAVIOR"
        confidence_score = confidence_score if confidence_score is not None else score

    if classification is None:
        classification = EvidenceClassificationEngine.classify_event(
            event_type, details
        )

    desc = build_finding_explanation(
        event=event,
        finding_title=finding_title,
        finding_type=finding_type,
        confidence_score=confidence_score,
        classification=classification,
    )

    finding = Finding(
        case_id=case_id,
        event_id=getattr(event, "event_id", None),
        finding_title=finding_title,
        finding_type=finding_type,
        description=desc,
        confidence_score=confidence_score,
        validation_status=validation_status,
        investigator_notes=investigator_notes,
    )
    if hasattr(event, "_sa_instance_state"):
        finding.event = event
    else:
        finding._mock_event = event
    finding.behavior_classification = classification.get("primary_category")
    finding.classification_confidence = classification.get("confidence")
    reasons = classification.get("reasons", [])
    finding.classification_reason = reasons[-1] if reasons else None
    finding.classification = classification
    return finding


@router.get("/cases/{case_id}/findings", response_model=List[FindingResponse])
def list_findings(case_id: str, db: Session = Depends(get_db)):
    """Lists all investigative findings with validation status and supporting event link."""

    findings = (
        db.query(Finding)
        .filter(Finding.case_id == case_id)
        .order_by(Finding.confidence_score.desc())
        .all()
    )

    results = []

    for f in findings:
        resp = FindingResponse.model_validate(f)

        if f.event:
            resp.linked_event = f.event
            cls_out = EvidenceClassificationEngine.classify_event(
                f.event.event_type, f.event.details or {}
            )
            resp.behavior_classification = cls_out.get("primary_category")
            resp.classification_confidence = cls_out.get("confidence")
            reasons = cls_out.get("reasons", [])
            resp.classification_reason = reasons[-1] if reasons else None
            resp.classification = cls_out
        elif f.behavior_classification:
            resp.behavior_classification = f.behavior_classification
            resp.classification_confidence = f.classification_confidence
            resp.classification_reason = f.classification_reason
            resp.classification = f.classification

        results.append(resp)

    return results


@router.patch("/findings/{finding_id}/validate", response_model=FindingResponse)
def validate_finding(
    finding_id: str, payload: FindingUpdate, db: Session = Depends(get_db)
):
    """
    Examiner Validation Gate.

    Enforces mandatory human-in-the-loop review. The lead forensic examiner
    accepts, rejects, or modifies AI-correlated findings before they are
    included in court-ready reports.
    """

    finding = db.query(Finding).filter(Finding.finding_id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_status = finding.validation_status

    finding.validation_status = payload.validation_status

    if payload.investigator_notes:
        finding.investigator_notes = payload.investigator_notes

    if payload.finding_title:
        finding.finding_title = payload.finding_title

    if payload.description:
        finding.description = payload.description

    # Log to audit trail
    db.add(
        AuditLog(
            case_id=finding.case_id,
            user_name="Forensic Examiner (Validation Gate)",
            action="FINDING_VALIDATION_UPDATED",
            details=(
                f"Finding '{finding.finding_title}' updated from "
                f"{old_status} -> {payload.validation_status}. "
                f"Notes: {payload.investigator_notes or 'None'}"
            ),
        )
    )

    db.commit()
    db.refresh(finding)

    resp = FindingResponse.model_validate(finding)

    if finding.event:
        resp.linked_event = finding.event
        cls_out = EvidenceClassificationEngine.classify_event(
            finding.event.event_type, finding.event.details or {}
        )
        resp.behavior_classification = cls_out.get("primary_category")
        resp.classification_confidence = cls_out.get("confidence")
        reasons = cls_out.get("reasons", [])
        resp.classification_reason = reasons[-1] if reasons else None
        resp.classification = cls_out
    elif finding.behavior_classification:
        resp.behavior_classification = finding.behavior_classification
        resp.classification_confidence = finding.classification_confidence
        resp.classification_reason = finding.classification_reason
        resp.classification = finding.classification

    return resp


@router.post("/cases/{case_id}/correlate", response_model=Dict[str, Any])
def run_correlation_and_detection(case_id: str, db: Session = Depends(get_db)):
    """
    Executes behavioral anomaly detection and detail-aware
    cross-event correlation across normalized forensic events.

    The anomaly engine performs event-level detection.

    The correlation layer examines:
    - event type
    - timestamps
    - host
    - user
    - process image
    - parent process
    - process IDs
    - created files
    - accessed targets
    - network destinations
    - archive/file relationships

    It then constructs multi-event behavioral attack chains
    using strong evidence-backed relationships.
    """

    case = db.query(Case).filter(Case.case_id == case_id).first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # ---------------------------------------------------------
    # Retrieve all normalized events for this case
    # ---------------------------------------------------------

    events = (
        db.query(Event)
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id)
        .all()
    )

    new_findings_count = 0
    anomalies_updated = 0

    # M2 evidence classification is computed alongside the existing
    # anomaly pass and integrated into AI findings.
    (
        event_classifications,
        classification_summary,
    ) = classify_events_for_m2(events)

    # ---------------------------------------------------------
    # 1. Existing anomaly detection
    # ---------------------------------------------------------

    for ev in events:
        is_anom, score, title, ftype = AnomalyDetectionEngine.evaluate_event(
            ev.event_type, ev.details or {}
        )

        if is_anom:
            ev.is_anomalous = 1
            ev.anomaly_score = score

            anomalies_updated += 1

            # Propose finding if none already exists for this event
            existing_f = (
                db.query(Finding)
                .filter(
                    Finding.case_id == case_id,
                    Finding.event_id == ev.event_id,
                )
                .first()
            )

            cls_data = event_classifications.get(ev.event_id)
            if not cls_data:
                cls_data = EvidenceClassificationEngine.classify_event(
                    ev.event_type, ev.details or {}
                )

            if not existing_f and title and ftype:
                new_finding = Finding(
                    case_id=case_id,
                    event_id=ev.event_id,
                    finding_title=title,
                    finding_type=ftype,
                    description=build_finding_explanation(
                        event=ev,
                        finding_title=title,
                        finding_type=ftype,
                        confidence_score=score,
                        classification=cls_data,
                    ),
                    confidence_score=score,
                    validation_status="Pending",
                    investigator_notes=(
                        "Generated by Anomaly Engine; awaiting examiner review."
                    ),
                )
                new_finding.event = ev
                new_finding.behavior_classification = cls_data.get("primary_category")
                new_finding.classification_confidence = cls_data.get("confidence")
                cls_reasons = cls_data.get("reasons", [])
                new_finding.classification_reason = cls_reasons[-1] if cls_reasons else None
                new_finding.classification = cls_data
                db.add(new_finding)
                new_findings_count += 1

            elif (
                existing_f is not None
                and existing_f.validation_status == "Pending"
                and title is not None
                and ftype is not None
            ):
                existing_f.finding_title = title
                existing_f.finding_type = ftype
                existing_f.description = build_finding_explanation(
                    event=ev,
                    finding_title=title,
                    finding_type=ftype,
                    confidence_score=score,
                    classification=cls_data,
                )
                existing_f.confidence_score = score
                existing_f.behavior_classification = cls_data.get("primary_category")
                existing_f.classification_confidence = cls_data.get("confidence")
                cls_reasons = cls_data.get("reasons", [])
                existing_f.classification_reason = cls_reasons[-1] if cls_reasons else None
                existing_f.classification = cls_data

    db.commit()

    # ---------------------------------------------------------
    # 2. Detail-aware behavioral correlation
    # ---------------------------------------------------------

    correlations = []

    anomalous_events = [ev for ev in events if getattr(ev, "is_anomalous", 0)]

    anomalous_events.sort(key=lambda ev: ev.timestamp)

    def get_details(event):
        """Safely return event details as a dictionary."""
        return event.details if event and isinstance(event.details, dict) else {}

    def normalize(value):
        """Normalize a value for comparison."""
        if value is None:
            return ""

        return str(value).lower().replace("\\", "/")

    def process_name(value):
        """Extract a normalized executable name."""
        value = normalize(value)

        if not value:
            return ""

        return value.split("/")[-1]

    def same_value(value1, value2):
        """Case-insensitive normalized value comparison."""
        return bool(value1) and bool(value2) and normalize(value1) == normalize(value2)

    def contains_value(value, target):
        """Check whether target occurs inside a normalized value."""
        value = normalize(value)
        target = normalize(target)

        return bool(value and target and target in value)

    def get_process_id(event):
        details = get_details(event)
        return str(details.get("process_id", ""))

    def get_created_by_pid(event):
        details = get_details(event)
        return str(details.get("created_by_pid", ""))

    def get_image(event):
        details = get_details(event)
        return details.get("image", "")

    def get_parent_image(event):
        details = get_details(event)
        return details.get("parent_image", "")

    def get_target_filename(event):
        details = get_details(event)
        return details.get("target_filename", "")

    def get_target_accessed(event):
        details = get_details(event)
        return details.get("target_accessed", "")

    # ---------------------------------------------------------
    # 3. Compare event pairs
    # ---------------------------------------------------------

    for i, first in enumerate(anomalous_events):
        for second in anomalous_events[i + 1 :]:
            if not first.timestamp or not second.timestamp:
                continue

            # Only forward chronological relationships
            if second.timestamp < first.timestamp:
                continue

            time_gap = (second.timestamp - first.timestamp).total_seconds()

            # Ignore distant events
            if time_gap > 600:
                break

            shared_host = (
                bool(first.host_ip)
                and bool(second.host_ip)
                and first.host_ip == second.host_ip
            )

            shared_user = (
                bool(first.user_account)
                and bool(second.user_account)
                and first.user_account == second.user_account
            )

            first_details = get_details(first)
            second_details = get_details(second)

            relationship_type = None
            relationship_reason = None
            relationship_score = 0.0

            # -------------------------------------------------
            # Relationship 1:
            # Parent process → child process
            # -------------------------------------------------

            first_process_id = get_process_id(first)
            second_parent_image = get_parent_image(second)

            first_image_name = process_name(get_image(first))

            if (
                first.event_type == "PROCESS_CREATE"
                and second.event_type == "PROCESS_CREATE"
                and first_image_name
                and second_parent_image
                and contains_value(
                    second_parent_image,
                    first_image_name,
                )
            ):
                relationship_type = "PROCESS_PARENT_CHILD"

                relationship_reason = (
                    "The second process identifies the first process "
                    "as its parent process."
                )

                relationship_score = 0.95

            # -------------------------------------------------
            # Relationship 2:
            # Process → File Drop
            # -------------------------------------------------

            elif (
                first.event_type == "PROCESS_CREATE"
                and second.event_type in ("FILE_DROP", "FILE_CREATE")
            ):
                created_by_pid = get_created_by_pid(second)

                if (
                    first_process_id
                    and created_by_pid
                    and first_process_id == created_by_pid
                ):
                    relationship_type = "PROCESS_CREATED_FILE"

                    relationship_reason = (
                        "The file was created by the process "
                        "identified in the preceding execution event."
                    )

                    relationship_score = 0.98

            # -------------------------------------------------
            # Relationship 3:
            # File Drop → Registry Persistence
            # -------------------------------------------------

            elif (
                first.event_type in ("FILE_DROP", "FILE_CREATE")
                and second.event_type in ("REGISTRY_PERSISTENCE", "REGISTRY_WRITE")
            ):
                dropped_file = get_target_filename(first)

                registry_value = second_details.get(
                    "value_data",
                    "",
                )

                if (
                    dropped_file
                    and registry_value
                    and same_value(
                        dropped_file,
                        registry_value,
                    )
                ):
                    relationship_type = "DROPPED_FILE_PERSISTENCE"

                    relationship_reason = (
                        "The persistence mechanism references "
                        "the executable previously dropped on the host."
                    )

                    relationship_score = 0.98

            # -------------------------------------------------
            # Relationship 4:
            # Persistence → Credential Access
            #
            # Link a persistence mechanism to a later credential-
            # access process when the persisted executable is the
            # same executable that accessed LSASS.
            # -------------------------------------------------

            elif (
                first.event_type == "REGISTRY_PERSISTENCE"
                and second.event_type == "PROCESS_CREATE"
            ):
                persisted_executable = first_details.get(
                    "value_data",
                    "",
                )

                credential_process = get_image(second)

                target_accessed = get_target_accessed(second)

                if (
                    persisted_executable
                    and credential_process
                    and target_accessed
                    and same_value(
                        persisted_executable,
                        credential_process,
                    )
                    and "lsass.exe" in normalize(target_accessed)
                ):
                    relationship_type = "PERSISTENCE_TO_CREDENTIAL_ACCESS"

                    relationship_reason = (
                        "The credential-accessing process executed from "
                        "the same executable path established by the earlier "
                        "registry persistence mechanism and accessed LSASS."
                    )

                    relationship_score = 0.95

            # -------------------------------------------------
            # Relationship 5:
            # Process → Credential Access
            #
            # Only create this relationship when the credential-
            # accessing process can be directly linked to the
            # preceding process through an explicit PID/parent
            # relationship.
            # -------------------------------------------------

            elif (
                first.event_type == "PROCESS_CREATE"
                and second.event_type == "PROCESS_CREATE"
            ):
                target_accessed = get_target_accessed(second)

                second_parent_pid = str(
                    second_details.get(
                        "parent_pid",
                        "",
                    )
                )

                first_process_id = get_process_id(first)

                if (
                    target_accessed
                    and "lsass.exe" in normalize(target_accessed)
                    and first_process_id
                    and second_parent_pid
                    and first_process_id == second_parent_pid
                ):
                    relationship_type = "PROCESS_TO_CREDENTIAL_ACCESS"

                    relationship_reason = (
                        "The credential-accessing process is directly "
                        "linked to the preceding process through its "
                        "parent process ID and accessed LSASS."
                    )

                    relationship_score = 0.97

            # -------------------------------------------------
            # Relationship 6:
            # Process → Network
            # -------------------------------------------------

            elif (
                first.event_type == "PROCESS_CREATE"
                and second.event_type == "NETWORK_CONNECTION"
            ):
                process_details = first_details
                network_details = second_details

                target_archive = process_details.get(
                    "target_archive",
                    "",
                )

                command_line = process_details.get(
                    "command_line",
                    "",
                )

                protocol = normalize(network_details.get("protocol", ""))

                bytes_transferred = network_details.get(
                    "bytes_transferred",
                    0,
                )

                dst_ip = network_details.get(
                    "dst_ip",
                    "",
                )

                # Stronger evidence-backed relationship for a possible
                # archive creation followed by external data transfer.
                if (
                    target_archive
                    and (
                        "7z" in normalize(command_line)
                        or target_archive.lower().endswith(
                            (".7z", ".zip", ".rar", ".tar", ".gz")
                        )
                    )
                    and protocol
                    in {
                        "https",
                        "http",
                        "tls",
                    }
                    and dst_ip
                ):
                    try:
                        transferred_bytes = int(bytes_transferred or 0)
                    except (TypeError, ValueError):
                        transferred_bytes = 0

                    if transferred_bytes >= 10000000:
                        relationship_type = "ARCHIVE_TO_EXTERNAL_TRANSFER"

                        relationship_reason = (
                            "A process created an archive before a "
                            "subsequent external HTTPS/TLS network "
                            "connection transferred a substantial "
                            "volume of data."
                        )

                        relationship_score = 0.94

                # Preserve the existing generic process → network
                # relationship when archive-specific evidence is absent.
                if relationship_type is None and dst_ip:
                    relationship_type = "PROCESS_TO_NETWORK"

                    relationship_reason = (
                        "Network activity followed the process execution "
                        "on the same host."
                    )

                    relationship_score = 0.75

                    # Large outbound transfer provides stronger evidence.
                    try:
                        if int(bytes_transferred or 0) >= 10000000:
                            relationship_score = 0.90

                    except (TypeError, ValueError):
                        pass

            # -------------------------------------------------
            # Relationship 7:
            # Network → Process
            # -------------------------------------------------

            elif (
                first.event_type == "NETWORK_CONNECTION"
                and second.event_type == "PROCESS_CREATE"
            ):
                relationship_type = "NETWORK_TO_PROCESS"

                relationship_reason = (
                    "Process execution followed network activity on the same host."
                )

                relationship_score = 0.70

            # -------------------------------------------------
            # Relationship 8:
            # Network → Network
            # -------------------------------------------------

            elif (
                first.event_type == "NETWORK_CONNECTION"
                and second.event_type == "NETWORK_CONNECTION"
            ):
                first_network = first_details
                second_network = second_details

                first_dst = first_network.get(
                    "dst_ip",
                    "",
                )

                second_dst = second_network.get(
                    "dst_ip",
                    "",
                )

                if first_dst and second_dst:
                    relationship_type = "NETWORK_ACTIVITY_SEQUENCE"

                    relationship_reason = (
                        "Multiple network activities occurred "
                        "in close temporal proximity on the same host."
                    )

                    relationship_score = 0.65

            # -------------------------------------------------
            # Generic contextual support
            # -------------------------------------------------

            if relationship_type is None:
                continue

            # Require host or user context.
            if not (shared_host or shared_user):
                continue

            # Add contextual score where applicable.
            if shared_host:
                relationship_score += 0.03

            if shared_user:
                relationship_score += 0.02

            # Very close timing provides additional confidence.
            if time_gap <= 30:
                relationship_score += 0.03

            elif time_gap <= 120:
                relationship_score += 0.02

            relationship_score = min(
                1.0,
                round(relationship_score, 2),
            )

            correlations.append(
                {
                    "event_1": first.event_id,
                    "event_2": second.event_id,
                    "event_1_type": first.event_type,
                    "event_2_type": second.event_type,
                    "time_gap_seconds": int(time_gap),
                    "shared_host": shared_host,
                    "shared_user": shared_user,
                    "relationship_type": relationship_type,
                    "correlation_score": relationship_score,
                    "correlation_reason": relationship_reason,
                }
            )

    # ---------------------------------------------------------
    # 4. Sort strongest relationships first
    # ---------------------------------------------------------

    correlations.sort(
        key=lambda item: (
            item["correlation_score"],
            -item["time_gap_seconds"],
        ),
        reverse=True,
    )

    # ---------------------------------------------------------
    # 5. Build multi-event behavioral attack chains
    # ---------------------------------------------------------

    attack_chains = []

    # Create quick lookup for event objects.
    event_lookup = {ev.event_id: ev for ev in anomalous_events}

    # Only strong, evidence-backed relationships are allowed
    # to construct an attack chain.
    strong_relationships = [
        item
        for item in correlations
        if item["correlation_score"] >= 0.90
        and item["relationship_type"]
        in {
            "PROCESS_PARENT_CHILD",
            "PROCESS_CREATED_FILE",
            "DROPPED_FILE_PERSISTENCE",
            "PERSISTENCE_TO_CREDENTIAL_ACCESS",
            "PROCESS_TO_CREDENTIAL_ACCESS",
            "ARCHIVE_TO_EXTERNAL_TRANSFER",
        }
    ]

    # ---------------------------------------------------------
    # Build adjacency graph
    # ---------------------------------------------------------

    adjacency = {}

    for relationship in strong_relationships:
        source = relationship["event_1"]
        target = relationship["event_2"]

        adjacency.setdefault(
            source,
            [],
        ).append(relationship)

    # ---------------------------------------------------------
    # Find chains using depth-first traversal
    # ---------------------------------------------------------

    def extend_chain(
        current_event_id,
        current_chain,
        visited,
    ):
        next_relationships = adjacency.get(
            current_event_id,
            [],
        )

        if not next_relationships:
            if len(current_chain) >= 3:
                attack_chains.append(current_chain)

            return

        extended = False

        for relationship in next_relationships:
            next_event_id = relationship["event_2"]

            # Prevent cycles.
            if next_event_id in visited:
                continue

            next_event = event_lookup.get(next_event_id)

            next_event_details = get_details(next_event)

            extended = True

            extend_chain(
                next_event_id,
                current_chain
                + [
                    {
                        "event_id": next_event_id,
                        "event_type": relationship["event_2_type"],
                        "relationship_from_previous": (
                            relationship["relationship_type"]
                        ),
                        "relationship_reason": (relationship["correlation_reason"]),
                        "correlation_score": (relationship["correlation_score"]),
                        "timestamp": (
                            next_event.timestamp.isoformat()
                            if next_event and next_event.timestamp
                            else None
                        ),
                        "source_entity": (
                            next_event.source_entity if next_event else None
                        ),
                        "user_account": (
                            next_event.user_account if next_event else None
                        ),
                        "host_ip": (next_event.host_ip if next_event else None),
                        "evidence_context": (next_event_details),
                    }
                ],
                visited | {next_event_id},
            )

        # If this branch cannot continue, preserve the
        # current chain if it contains enough events.
        if not extended and len(current_chain) >= 3:
            attack_chains.append(current_chain)

    # ---------------------------------------------------------
    # Start chains from events that are not targets of
    # another strong relationship.
    # ---------------------------------------------------------

    relationship_targets = {item["event_2"] for item in strong_relationships}

    relationship_sources = {item["event_1"] for item in strong_relationships}

    chain_starts = relationship_sources - relationship_targets

    for start_event_id in chain_starts:
        start_event = event_lookup.get(start_event_id)

        if not start_event:
            continue

        extend_chain(
            start_event_id,
            [
                {
                    "event_id": start_event.event_id,
                    "event_type": start_event.event_type,
                    "relationship_from_previous": None,
                    "relationship_reason": (
                        "Starting event in correlated behavioral chain."
                    ),
                    "correlation_score": (
                        getattr(
                            start_event,
                            "anomaly_score",
                            None,
                        )
                    ),
                    "timestamp": (
                        start_event.timestamp.isoformat()
                        if start_event.timestamp
                        else None
                    ),
                    "source_entity": (start_event.source_entity),
                    "user_account": (start_event.user_account),
                    "host_ip": (start_event.host_ip),
                    "evidence_context": (get_details(start_event)),
                }
            ],
            {start_event_id},
        )

    # ---------------------------------------------------------
    # Remove duplicate chains
    # ---------------------------------------------------------

    unique_chains = []

    seen_chain_signatures = set()

    for chain in attack_chains:
        signature = tuple(item["event_id"] for item in chain)

        if signature in seen_chain_signatures:
            continue

        seen_chain_signatures.add(signature)

        unique_chains.append(chain)

    attack_chains = unique_chains

    # ---------------------------------------------------------
    # Assign human-readable chain descriptions
    # ---------------------------------------------------------

    formatted_attack_chains = []

    for index, chain in enumerate(
        attack_chains,
        start=1,
    ):
        event_types = [item["event_type"] for item in chain]

        # Do not treat the starting event's anomaly score
        # as a correlation edge.
        relationship_scores = [
            item["correlation_score"]
            for item in chain[1:]
            if item["correlation_score"] is not None
        ]

        overall_confidence = (
            round(
                min(relationship_scores),
                2,
            )
            if relationship_scores
            else None
        )

        formatted_attack_chains.append(
            {
                "chain_id": f"CHAIN-{index:03d}",
                "event_count": len(chain),
                "event_sequence": event_types,
                "overall_confidence": overall_confidence,
                "events": chain,
            }
        )

    # ---------------------------------------------------------
    # 6. Map findings to MITRE ATT&CK and persist AttackNodes
    # ---------------------------------------------------------
    case_findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    attack_nodes_created = 0
    for f in case_findings:
        existing_node = (
            db.query(AttackNode)
            .filter(
                AttackNode.case_id == case_id,
                AttackNode.finding_id == f.finding_id,
            )
            .first()
        )
        stage_name, stage_order, mitre_technique = (
            MitreAttackMapper.map_finding_to_stage(
                f.finding_title, f.description, f.finding_type
            )
        )
        if not existing_node:
            new_node = AttackNode(
                case_id=case_id,
                finding_id=f.finding_id,
                mitre_technique=mitre_technique,
                stage_name=stage_name,
                stage_order=stage_order,
                description=f.finding_title,
            )
            db.add(new_node)
            attack_nodes_created += 1
        else:
            existing_node.mitre_technique = mitre_technique
            existing_node.stage_name = stage_name
            existing_node.stage_order = stage_order
            existing_node.description = f.finding_title

    db.commit()

    # ---------------------------------------------------------
    # 7. Return correlation results
    # ---------------------------------------------------------

    return {
        "status": "Correlation complete",
        "events_scanned": len(events),
        "anomalous_events_flagged": anomalies_updated,
        "classified_events": len(event_classifications),
        "classification_summary": classification_summary,
        "event_classifications": event_classifications,
        "new_findings_proposed": new_findings_count,
        "correlations_found": len(correlations),
        "correlations": correlations,
        "attack_chains_found": len(formatted_attack_chains),
        "attack_chains": formatted_attack_chains,
        "attack_nodes_persisted": attack_nodes_created,
    }
