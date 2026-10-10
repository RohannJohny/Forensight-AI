from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.models import Case, Evidence, Artifact, Event
from app.schemas.schemas import EventResponse

router = APIRouter(tags=["Forensic Timeline & Analysis (Module 3)"])


@router.get("/cases/{case_id}/timeline", response_model=List[EventResponse])
def get_chronological_timeline(
    case_id: str,
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    user_account: Optional[str] = Query(None, description="Filter by user account"),
    host_ip: Optional[str] = Query(None, description="Filter by IP address"),
    only_anomalous: bool = Query(False, description="Show only flagged anomalous events"),
    search: Optional[str] = Query(None, description="Keyword search within event details"),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """
    Constructs a unified, standardized chronological timeline across all heterogeneous
    evidence artifacts (Windows Event logs, Sysmon, Registry, Volatility, Network flows).
    """
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    query = (
        db.query(Event)
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id)
    )

    if event_type:
        query = query.filter(Event.event_type == event_type.upper())
    if user_account:
        query = query.filter(Event.user_account.ilike(f"%{user_account}%"))
    if host_ip:
        query = query.filter(Event.host_ip.ilike(f"%{host_ip}%"))
    if only_anomalous:
        query = query.filter(Event.is_anomalous == 1)

    events = query.order_by(Event.timestamp.asc()).limit(limit).all()

    if search:
        s_lower = search.lower()
        events = [
            e for e in events
            if s_lower in str(e.details).lower()
            or s_lower in e.event_type.lower()
            or s_lower in (e.user_account or "").lower()
            or s_lower in (e.host_ip or "").lower()
            or s_lower in e.source_entity.lower()
        ]

    return events


@router.get("/cases/{case_id}/events/{event_id}", response_model=EventResponse)
def get_event_details(case_id: str, event_id: str, db: Session = Depends(get_db)):
    """Retrieves deep forensic details and raw parser attributes for an event."""
    ev = db.query(Event).filter(Event.event_id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev
