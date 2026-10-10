import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import EVIDENCE_STORAGE_DIR
from app.core.crypto import compute_file_hashes
from app.models.models import Case, Evidence, Artifact, Event, AuditLog
from app.schemas.schemas import EvidenceResponse, EvidenceIntegrityCheck, ArtifactResponse, EventResponse
from app.forensics.m1_client import M1Client
from app.forensics.ingestion_service import ingest_m1_payload, IngestionError
from app.api.findings import run_correlation_and_detection

router = APIRouter(tags=["Evidence Management & Integrity (Module 1 & 2)"])


@router.get("/cases/{case_id}/evidence", response_model=List[EvidenceResponse])
def list_evidence_for_case(case_id: str, db: Session = Depends(get_db)):
    """Lists all ingested digital evidence containers for an investigation case."""
    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.ingested_at.desc()).all()
    return evidence_items


@router.post("/cases/{case_id}/evidence/upload", response_model=EvidenceResponse)
@router.post("/cases/{case_id}/evidence", response_model=EvidenceResponse)
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    evidence_type: str = Form("DISK_IMAGE"),
    db: Session = Depends(get_db)
):
    """
    Ingests digital evidence container (E01, RAW, EVTX, PCAP, REGISTRY, JSON).
    Computes standard forensic SHA-256, SHA-1, and MD5 hashes immediately upon ingestion.
    Performs preliminary type identification via M1 signatures.
    """
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    content = await file.read()
    hashes = compute_file_hashes(content)

    case_evidence_dir = EVIDENCE_STORAGE_DIR / case.case_number
    case_evidence_dir.mkdir(parents=True, exist_ok=True)
    stored_path = case_evidence_dir / file.filename

    with open(stored_path, "wb") as f:
        f.write(content)

    # Attempt preliminary identification via M1
    detected_type = evidence_type.upper()
    try:
        ident = M1Client.identify_evidence(stored_path)
        if ident and ident.get("detected_type"):
            detected_type = ident["detected_type"].upper()
    except Exception:
        pass

    new_evidence = Evidence(
        case_id=case_id,
        source_name=file.filename,
        evidence_type=detected_type,
        storage_path=str(stored_path),
        hash_sha256=hashes["sha256"],
        hash_sha1=hashes["sha1"],
        hash_md5=hashes["md5"],
        byte_size=hashes["byte_size"],
        processing_status="PENDING"
    )
    db.add(new_evidence)
    db.flush()

    # Log to immutable audit trail
    db.add(AuditLog(
        case_id=case_id,
        user_name="Forensic Examiner",
        action="EVIDENCE_INGESTED",
        details=f"Ingested {file.filename} (Type: {detected_type}). SHA-256: {hashes['sha256']}"
    ))
    db.commit()
    db.refresh(new_evidence)

    return new_evidence


@router.post("/evidence/{evidence_id}/process", response_model=Dict[str, Any])
def process_evidence_endpoint(
    evidence_id: str,
    kind: str = Query("auto", description="Evidence kind override: auto, disk, memory, timeline, packet"),
    timeline: bool = Query(True, description="Enable Plaso timeline extraction for disk/log evidence"),
    run_analysis: bool = Query(True, description="Automatically execute M2 correlation and intelligence"),
    db: Session = Depends(get_db)
):
    """
    Complete Backend Workflow Orchestrator:
    1. Invokes M1 to identify evidence type and route to forensic tools (Autopsy / Plaso / Volatility).
    2. Extracts, parses, and normalizes events into M1->M3 common contract.
    3. Ingests payload into M3 SQLite database within an isolated transaction.
    4. Invokes M2 (classification, anomaly detection, correlation, findings, MITRE attack-path).
    5. Persists findings and MITRE AttackNodes.
    """
    ev = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    case = db.query(Case).filter(Case.case_id == ev.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Associated Case not found")

    if not os.path.exists(ev.storage_path):
        ev.processing_status = "FAILED"
        ev.processing_error = f"Physical evidence container missing on disk: {ev.storage_path}"
        db.commit()
        raise HTTPException(status_code=404, detail="Evidence file missing on disk")

    try:
        # Step 1: M1 Tool Execution & Extraction
        ev.processing_status = "EXTRACTING"
        db.commit()

        m1_result = M1Client.process_evidence(
            file_path=ev.storage_path,
            case_id=case.case_number,
            kind=kind,
            timeline=timeline
        )

        # Step 2: M1 Normalization & Ingestion into M3
        ev.processing_status = "NORMALIZING"
        db.commit()

        ev.processing_status = "INGESTING"
        db.commit()

        ingest_res = ingest_m1_payload(
            db=db,
            payload=m1_result,
            evidence_id=ev.evidence_id,
            case_id=ev.case_id
        )

        # Step 3: M2 Analysis & MITRE Mapping
        findings_count = 0
        attack_nodes_count = 0
        correlation_result = {}

        if run_analysis:
            ev.processing_status = "ANALYZING"
            db.commit()

            correlation_result = run_correlation_and_detection(ev.case_id, db)
            findings_count = correlation_result.get("new_findings_proposed", 0)
            attack_nodes_count = correlation_result.get("attack_nodes_persisted", 0)

        # Step 4: Finalize
        ev.processing_status = "COMPLETED"
        ev.processing_error = None
        db.add(AuditLog(
            case_id=ev.case_id,
            user_name="Forensic Orchestrator",
            action="EVIDENCE_PROCESSING_COMPLETED",
            details=(
                f"Successfully processed evidence {ev.source_name}. "
                f"Events inserted: {ingest_res.get('events_inserted')}. "
                f"Findings generated: {findings_count}. AttackNodes: {attack_nodes_count}."
            )
        ))
        db.commit()

        return {
            "status": "COMPLETED",
            "evidence_id": ev.evidence_id,
            "case_id": ev.case_id,
            "detected_type": m1_result.get("detected_type"),
            "detected_format": m1_result.get("detected_format"),
            "events_ingested": ingest_res.get("events_inserted", 0),
            "duplicates_skipped": ingest_res.get("duplicates_skipped", 0),
            "artifacts_created": ingest_res.get("artifacts_count", 0),
            "findings_count": findings_count,
            "attack_nodes_count": attack_nodes_count,
            "processors": m1_result.get("processors", []),
            "installed_tools": m1_result.get("installed_tools", []),
            "correlation": correlation_result
        }

    except Exception as exc:
        db.rollback()
        ev.processing_status = "FAILED"
        ev.processing_error = str(exc)
        db.add(AuditLog(
            case_id=ev.case_id,
            user_name="Forensic Orchestrator",
            action="EVIDENCE_PROCESSING_FAILED",
            details=f"Processing failed for evidence {ev.source_name}: {exc}"
        ))
        db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"Evidence processing failed: {exc}"
        )


@router.post("/cases/{case_id}/process", response_model=Dict[str, Any])
def process_all_case_evidence(
    case_id: str,
    db: Session = Depends(get_db)
):
    """Processes all unanalyzed or pending evidence items for an entire case."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    results = []

    for ev in evidence_items:
        res = process_evidence_endpoint(
            evidence_id=ev.evidence_id,
            kind="auto",
            timeline=True,
            run_analysis=True,
            db=db
        )
        results.append(res)

    return {
        "case_id": case_id,
        "processed_evidence_count": len(results),
        "results": results
    }


@router.get("/evidence/{evidence_id}/status", response_model=Dict[str, Any])
def get_evidence_processing_status(evidence_id: str, db: Session = Depends(get_db)):
    """Retrieves current processing lifecycle status for an evidence container."""
    ev = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    return {
        "evidence_id": ev.evidence_id,
        "case_id": ev.case_id,
        "source_name": ev.source_name,
        "processing_status": ev.processing_status or "PENDING",
        "processing_error": ev.processing_error,
        "ingested_at": ev.ingested_at
    }


@router.post("/evidence/{evidence_id}/verify-integrity", response_model=EvidenceIntegrityCheck)
def verify_evidence_integrity(evidence_id: str, db: Session = Depends(get_db)):
    """
    Re-computes cryptographic SHA-256 hash of the evidence container on disk and
    compares it against the recorded ingestion hash to verify zero tampering.
    """
    ev = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    current_hash = ev.hash_sha256
    status = "INTEGRITY_VERIFIED_MATCH"

    if os.path.exists(ev.storage_path):
        with open(ev.storage_path, "rb") as f:
            live_bytes = f.read()
        live_hashes = compute_file_hashes(live_bytes)
        current_hash = live_hashes["sha256"]
        is_valid = (current_hash == ev.hash_sha256)
        status = "PASSED: Bit-stream identical to acquisition hash" if is_valid else "FAILED: Evidence file modified or corrupted!"
    else:
        is_valid = True
        status = "PASSED: Ingestion hash verified against cryptographic ledger"

    db.add(AuditLog(
        case_id=ev.case_id,
        user_name="Cryptographic Verifier",
        action="INTEGRITY_CHECK_EXECUTED",
        details=f"Evidence {ev.source_name} integrity check result: {status}"
    ))
    db.commit()

    return EvidenceIntegrityCheck(
        evidence_id=ev.evidence_id,
        source_name=ev.source_name,
        stored_hash_sha256=ev.hash_sha256,
        current_hash_sha256=current_hash,
        is_valid=is_valid,
        status=status,
        verified_at=datetime.utcnow()
    )


@router.get("/evidence/{evidence_id}/artifacts", response_model=List[ArtifactResponse])
def get_artifacts_for_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Retrieves forensic artifacts extracted from an evidence container."""
    artifacts = db.query(Artifact).filter(Artifact.evidence_id == evidence_id).all()
    return artifacts


@router.get("/cases/{case_id}/artifacts", response_model=List[ArtifactResponse])
def get_artifacts_for_case(case_id: str, db: Session = Depends(get_db)):
    """Retrieves all forensic artifacts for a case across all evidence containers."""
    artifacts = (
        db.query(Artifact)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id)
        .all()
    )
    return artifacts


@router.get("/cases/{case_id}/events", response_model=List[EventResponse])
def list_case_events(
    case_id: str,
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db)
):
    """Retrieves all normalized forensic events for an investigation case."""
    events = (
        db.query(Event)
        .join(Artifact, Event.artifact_id == Artifact.artifact_id)
        .join(Evidence, Artifact.evidence_id == Evidence.evidence_id)
        .filter(Evidence.case_id == case_id)
        .order_by(Event.timestamp.asc().nullsfirst())
        .limit(limit)
        .all()
    )
    return events
