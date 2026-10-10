from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db
from app.models.models import Case, Evidence, Event, Finding, Report, User, AuditLog, Artifact
from app.schemas.schemas import CaseCreate, CaseResponse, AuditLogResponse

router = APIRouter(prefix="/cases", tags=["Case Management (Module 1)"])


@router.get("", response_model=List[CaseResponse])
def list_cases(db: Session = Depends(get_db)):
    """Lists all forensic investigation cases with summary telemetry."""
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    results = []
    for c in cases:
        ev_count = db.query(func.count(Evidence.evidence_id)).filter(Evidence.case_id == c.case_id).scalar() or 0
        finding_count = db.query(func.count(Finding.finding_id)).filter(Finding.case_id == c.case_id).scalar() or 0
        
        # Count total events across all artifacts of this case
        event_count = (
            db.query(func.count(Event.event_id))
            .join(Artifact, Event.artifact_id == Artifact.artifact_id)
            .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
            .filter(Evidence.case_id == c.case_id)
            .scalar() or 0
        )

        results.append(CaseResponse(
            case_id=c.case_id,
            user_id=c.user_id,
            case_number=c.case_number,
            case_name=c.case_name,
            description=c.description,
            status=c.status,
            created_at=c.created_at,
            evidence_count=ev_count,
            event_count=event_count,
            finding_count=finding_count
        ))
    return results


@router.post("", response_model=CaseResponse)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)):
    """Initializes a new forensic investigation case with chain of custody tracking."""
    # Find or create default user if user_id is omitted
    if not payload.user_id:
        user = db.query(User).first()
        if not user:
            user = User(
                name="Lead Forensic Examiner",
                email="investigator@forensight.ai",
                password_hash="sha256$default$hash",
                role="Investigator"
            )
            db.add(user)
            db.flush()
        user_id = user.user_id
    else:
        user_id = payload.user_id

    # Check case number uniqueness
    existing = db.query(Case).filter(Case.case_number == payload.case_number).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Case number '{payload.case_number}' already exists.")

    new_case = Case(
        user_id=user_id,
        case_number=payload.case_number,
        case_name=payload.case_name,
        description=payload.description,
        status=payload.status
    )
    db.add(new_case)
    db.flush()

    db.add(AuditLog(
        case_id=new_case.case_id,
        user_name="Lead Investigator",
        action="CASE_INITIALIZED",
        details=f"Case {new_case.case_number} created: {new_case.case_name}"
    ))
    db.commit()
    db.refresh(new_case)

    return CaseResponse(
        case_id=new_case.case_id,
        user_id=new_case.user_id,
        case_number=new_case.case_number,
        case_name=new_case.case_name,
        description=new_case.description,
        status=new_case.status,
        created_at=new_case.created_at,
        evidence_count=0,
        event_count=0,
        finding_count=0
    )


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, db: Session = Depends(get_db)):
    """Retrieves specific case container metadata."""
    c = db.query(Case).filter(Case.case_id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    ev_count = db.query(func.count(Evidence.evidence_id)).filter(Evidence.case_id == c.case_id).scalar() or 0
    finding_count = db.query(func.count(Finding.finding_id)).filter(Finding.case_id == c.case_id).scalar() or 0
    event_count = (
        db.query(func.count(Event.event_id))
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == c.case_id)
        .scalar() or 0
    )

    return CaseResponse(
        case_id=c.case_id,
        user_id=c.user_id,
        case_number=c.case_number,
        case_name=c.case_name,
        description=c.description,
        status=c.status,
        created_at=c.created_at,
        evidence_count=ev_count,
        event_count=event_count,
        finding_count=finding_count
    )


@router.get("/{case_id}/stats", response_model=Dict[str, Any])
def get_case_statistics(case_id: str, db: Session = Depends(get_db)):
    """Returns high-level investigation telemetry metrics."""
    c = db.query(Case).filter(Case.case_id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence_count = db.query(func.count(Evidence.evidence_id)).filter(Evidence.case_id == case_id).scalar() or 0
    artifact_count = (
        db.query(func.count(Artifact.artifact_id))
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id)
        .scalar() or 0
    )
    event_count = (
        db.query(func.count(Event.event_id))
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id)
        .scalar() or 0
    )
    anomalies_count = (
        db.query(func.count(Event.event_id))
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id, Event.is_anomalous == 1)
        .scalar() or 0
    )
    findings_count = db.query(func.count(Finding.finding_id)).filter(Finding.case_id == case_id).scalar() or 0
    validated_findings = (
        db.query(func.count(Finding.finding_id))
        .filter(Finding.case_id == case_id, Finding.validation_status == "Accepted")
        .scalar() or 0
    )
    reports_count = db.query(func.count(Report.report_id)).filter(Report.case_id == case_id).scalar() or 0

    return {
        "case_id": case_id,
        "case_number": c.case_number,
        "case_name": c.case_name,
        "status": c.status,
        "evidence_count": evidence_count,
        "artifact_count": artifact_count,
        "event_count": event_count,
        "anomalous_events_count": anomalies_count,
        "total_findings": findings_count,
        "validated_findings": validated_findings,
        "finalized_reports": reports_count
    }


@router.get("/{case_id}/audit-logs", response_model=List[AuditLogResponse])
def get_case_audit_logs(case_id: str, db: Session = Depends(get_db)):
    """Returns immutable chain-of-custody audit logs."""
    logs = db.query(AuditLog).filter(AuditLog.case_id == case_id).order_by(AuditLog.timestamp.desc()).all()
    return logs


@router.post("/{case_id}/assistant/query")
def query_case_assistant(case_id: str, payload: Dict[str, Any], db: Session = Depends(get_db)):
    """Grounded AI investigation assistant endpoint scoped to a case."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    query_text = payload.get("query", "")
    events = (
        db.query(Event)
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id)
        .all()
    )
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    from app.ai.rag_assistant import EvidenceGroundedAssistant
    result = EvidenceGroundedAssistant.query(case, events, findings, query_text)
    return result
