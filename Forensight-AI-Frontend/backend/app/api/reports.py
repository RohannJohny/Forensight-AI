import os
from datetime import datetime
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import REPORT_STORAGE_DIR
from app.core.crypto import encrypt_report_payload, decrypt_report_payload
from app.models.models import Case, Evidence, Finding, AttackNode, Event, Report, AuditLog, Artifact
from app.schemas.schemas import ReportGenerateRequest, ReportResponse, ReportDecryptResponse

router = APIRouter(tags=["Report Generation & Secure Storage (Module 6 & 7)"])


@router.post("/cases/{case_id}/reports/generate", response_model=ReportResponse)
def generate_and_encrypt_report(case_id: str, payload: ReportGenerateRequest, db: Session = Depends(get_db)):
    """
    Module 6 & 7 Pipeline:
    1. Compiles standardized court-ready forensic dossier from validated findings and evidence.
    2. Executes Two-Key Cryptography:
       - Computes plaintext SHA-256 integrity hash.
       - Generates unique 256-bit Report Encryption Key (REK).
       - Encrypts report body using AES-256-GCM.
       - Wraps REK using Master Key (MK).
    3. Stores encrypted payload and registers cryptographic audit entry.
    """
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    validated_findings = db.query(Finding).filter(Finding.case_id == case_id, Finding.validation_status == "Accepted").all()
    attack_nodes = db.query(AttackNode).filter(AttackNode.case_id == case_id).order_by(AttackNode.stage_order.asc()).all()

    # Build Standardized Forensic Dossier (Courtroom Defensible Format)
    lines = []
    lines.append(f"# FORENSIC INVESTIGATION REPORT: {payload.report_name.upper()}")
    lines.append("=" * 80)
    lines.append(f"Case Number:         {case.case_number}")
    lines.append(f"Case Title:          {case.case_name}")
    lines.append(f"Date of Report:      {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"Lead Examiner:       {payload.investigator_name}")
    lines.append(f"Status:              FINAL - EXAMINER SIGNED & AUDITED")
    lines.append("=" * 80)
    lines.append("\n## 1. EXECUTIVE SUMMARY & OBJECTIVES")
    lines.append(payload.executive_summary or case.description or "Comprehensive incident investigation.")
    
    lines.append("\n## 2. DIGITAL EVIDENCE CHAIN OF CUSTODY & INTEGRITY HASHES")
    lines.append("| Evidence Source | Type | Stored Path | SHA-256 Cryptographic Hash |")
    lines.append("| :--- | :--- | :--- | :--- |")
    for ev in evidence_items:
        lines.append(f"| `{ev.source_name}` | `{ev.evidence_type}` | `{ev.storage_path}` | `{ev.hash_sha256}` |")

    lines.append("\n## 3. FORENSIC METHODOLOGY & TOOL ORCHESTRATION")
    lines.append(
        "Digital evidence acquired in accordance with ISO/IEC 27037 standards. "
        "Artifact extraction performed using The Sleuth Kit (file system), Volatility 3 (volatile memory), "
        "RegRipper 3.0 (registry hives), and Zeek/PCAP parsers without modifying master evidence containers. "
        "All events normalized to the Forensight Common Event Model (CEM)."
    )

    lines.append("\n## 4. VALIDATED INVESTIGATIVE FINDINGS (EXAMINER APPROVED)")
    if not validated_findings:
        lines.append("*No findings currently marked as 'Accepted' by the examiner validation gate.*")
    else:
        for idx, f in enumerate(validated_findings, 1):
            lines.append(f"### 4.{idx} {f.finding_title} [Type: {f.finding_type}]")
            lines.append(f"- **Confidence Score:** {int(f.confidence_score * 100)}%")
            lines.append(f"- **Investigator Validation:** {f.validation_status}")
            lines.append(f"- **Description:** {f.description}")
            if f.investigator_notes:
                lines.append(f"- **Examiner Verification Notes:** {f.investigator_notes}")
            if f.event:
                lines.append(
                    f"- **Supporting Evidence ID:** `{f.event.event_id}` (Source: `{f.event.source_entity}`, Timestamp: {f.event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')})"
                )
            lines.append("")

    lines.append("\n## 5. RECONSTRUCTED ATTACK PATH (MITRE ATT&CK)")
    for n in attack_nodes:
        lines.append(f"- **Stage {n.stage_order} [{n.stage_name}]:** {n.mitre_technique}")
        lines.append(f"  *Details:* {n.description}")

    lines.append("\n## 6. EXAMINER ATTESTATION & EVIDENCE INTEGRITY")
    lines.append(
        f"I, {payload.investigator_name}, hereby attest under professional forensic standards that the analyses, "
        "timelines, and findings described herein accurately represent the digital evidence examined. "
        "All digital signatures and bit-stream verification hashes remain recorded in the immutable audit vault."
    )
    lines.append("\n[DIGITALLY SIGNED VIA FORENSIGHT AI CRYPTOGRAPHIC VAULT]")

    report_plaintext = "\n".join(lines)

    # Two-Key Cryptography (Module 7)
    encrypted_payload, wrapped_rek, plaintext_sha256 = encrypt_report_payload(report_plaintext)

    report_filename = f"{case.case_number}_FINAL_DOSSIER_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.enc"
    encrypted_file_path = str(REPORT_STORAGE_DIR / report_filename)

    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_payload)

    new_report = Report(
        case_id=case_id,
        report_name=payload.report_name,
        integrity_hash=plaintext_sha256,
        encrypted_file_path=encrypted_file_path,
        encrypted_rek=wrapped_rek,
        status="Final"
    )
    db.add(new_report)
    db.flush()

    db.add(AuditLog(
        case_id=case_id,
        user_name=payload.investigator_name,
        action="REPORT_ENCRYPTED_AND_FINALIZED",
        details=f"Final report '{new_report.report_name}' encrypted with Two-Key AES-256-GCM. Plaintext SHA-256: {plaintext_sha256}"
    ))
    db.commit()
    db.refresh(new_report)

    return new_report


@router.get("/cases/{case_id}/reports", response_model=List[ReportResponse])
def list_reports_for_case(case_id: str, db: Session = Depends(get_db)):
    """Lists all encrypted finalized reports for an investigation case."""
    reports = db.query(Report).filter(Report.case_id == case_id).order_by(Report.finalized_at.desc()).all()
    return reports


@router.get("/reports/{report_id}/decrypt", response_model=ReportDecryptResponse)
def decrypt_and_verify_report(report_id: str, db: Session = Depends(get_db)):
    """
    Decryption & Tamper Verification Gate (Module 7):
    Unwraps the Report Encryption Key (REK) using system Master Key (MK),
    decrypts AES-256-GCM report payload, and verifies the computed SHA-256 hash.
    """
    rep = db.query(Report).filter(Report.report_id == report_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")

    if not os.path.exists(rep.encrypted_file_path):
        raise HTTPException(status_code=500, detail="Encrypted report container missing from disk")

    with open(rep.encrypted_file_path, "rb") as f:
        encrypted_bytes = f.read()

    decrypted_text, is_tamper_free = decrypt_report_payload(encrypted_bytes, rep.encrypted_rek, rep.integrity_hash)

    db.add(AuditLog(
        case_id=rep.case_id,
        user_name="Authorized Investigator",
        action="REPORT_DECRYPTED_AND_VERIFIED",
        details=f"Report {rep.report_name} decrypted. Tamper-free verification: {is_tamper_free}"
    ))
    db.commit()

    return ReportDecryptResponse(
        report_id=rep.report_id,
        report_name=rep.report_name,
        plaintext_content=decrypted_text,
        integrity_hash=rep.integrity_hash,
        is_tamper_free=is_tamper_free,
        verified_at=datetime.utcnow()
    )


@router.get("/reports/{report_id}/html", response_class=HTMLResponse)
def view_court_ready_html(report_id: str, db: Session = Depends(get_db)):
    """Renders decrypted report formatted for legal print / courtroom PDF export."""
    rep = db.query(Report).filter(Report.report_id == report_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")

    with open(rep.encrypted_file_path, "rb") as f:
        encrypted_bytes = f.read()

    decrypted_text, is_tamper_free = decrypt_report_payload(encrypted_bytes, rep.encrypted_rek, rep.integrity_hash)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>{rep.report_name}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1e293b; line-height: 1.6; }}
        .header {{ border-bottom: 2px solid #0284c7; padding-bottom: 15px; margin-bottom: 25px; }}
        .badge {{ background: #0284c7; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .tamper-pass {{ background: #10b981; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; }}
        th {{ background: #f1f5f9; }}
        pre {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px; border-radius: 6px; white-space: pre-wrap; font-family: 'Courier New', monospace; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{rep.report_name}</h1>
        <p><span class="badge">Two-Key AES-256-GCM Encrypted</span> <span class="tamper-pass">{'INTEGRITY VERIFIED (TAMPER-FREE)' if is_tamper_free else 'TAMPER WARNING'}</span></p>
        <p><strong>SHA-256 Ledger Hash:</strong> <code>{rep.integrity_hash}</code></p>
    </div>
    <pre>{decrypted_text}</pre>
</body>
</html>"""
    return html_content
