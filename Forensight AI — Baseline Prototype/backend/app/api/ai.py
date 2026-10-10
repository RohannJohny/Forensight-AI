from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.models import Case, Event, Finding, Artifact, Evidence
from app.schemas.schemas import AIChatQuery, AIChatResponse
from app.ai.rag_assistant import EvidenceGroundedAssistant

router = APIRouter(prefix="/ai", tags=["AI Investigation Assistant (Module 4)"])


@router.post("/query", response_model=AIChatResponse)
def query_ai_assistant(payload: AIChatQuery, db: Session = Depends(get_db)):
    """
    Modular, evidence-grounded AI conversational interface.
    Retrieves case records and provides factual explanations with explicit event IDs,
    artifact references, and timestamps. Never hallucinates outside ingested case records.
    """
    case = db.query(Case).filter(Case.case_id == payload.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Fetch all events belonging to this case
    events = (
        db.query(Event)
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == payload.case_id)
        .all()
    )

    findings = db.query(Finding).filter(Finding.case_id == payload.case_id).all()

    result = EvidenceGroundedAssistant.query(case, events, findings, payload.query)
    return AIChatResponse(**result)


@router.get("/cases/{case_id}/summary", response_model=AIChatResponse)
def get_case_ai_summary(case_id: str, db: Session = Depends(get_db)):
    """Generates an evidence-grounded executive incident summary."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    events = (
        db.query(Event)
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id)
        .all()
    )

    findings = db.query(Finding).filter(Finding.case_id == case_id).all()

    result = EvidenceGroundedAssistant.query(
        case,
        events,
        findings,
        "Summarize the complete incident timeline and attack sequence",
    )
    return AIChatResponse(**result)
