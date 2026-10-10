from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# --- User Schemas ---
class UserBase(BaseModel):
    name: str
    email: str
    role: str = "Investigator"


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    user_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# --- Case Schemas ---
class CaseBase(BaseModel):
    case_number: str
    case_name: str
    description: Optional[str] = None
    status: str = "Active"


class CaseCreate(CaseBase):
    user_id: Optional[str] = None


class CaseResponse(CaseBase):
    case_id: str
    user_id: str
    created_at: datetime
    evidence_count: Optional[int] = 0
    event_count: Optional[int] = 0
    finding_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


# --- Evidence Schemas ---
class EvidenceBase(BaseModel):
    source_name: str
    evidence_type: str


class EvidenceCreate(EvidenceBase):
    case_id: str


class EvidenceResponse(EvidenceBase):
    evidence_id: str
    case_id: str
    storage_path: str
    hash_sha256: str
    hash_sha1: Optional[str] = None
    hash_md5: Optional[str] = None
    byte_size: Optional[str] = None
    processing_status: Optional[str] = "COMPLETED"
    processing_error: Optional[str] = None
    ingested_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceIntegrityCheck(BaseModel):
    evidence_id: str
    source_name: str
    stored_hash_sha256: str
    current_hash_sha256: str
    is_valid: bool
    status: str
    verified_at: datetime


# --- Artifact Schemas ---
class ArtifactResponse(BaseModel):
    artifact_id: str
    evidence_id: str
    artifact_type: str
    parser_used: str
    raw_data: Optional[Dict[str, Any]] = None
    extracted_at: datetime

    model_config = ConfigDict(from_attributes=True)


# --- Event / Timeline Schemas ---
class EventResponse(BaseModel):
    event_id: str
    source_event_id: Optional[str] = None
    artifact_id: str
    timestamp: Optional[datetime] = None
    event_type: str
    source_entity: str
    user_account: Optional[str] = None
    host_ip: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    is_anomalous: int = 0
    anomaly_score: float = 0.0

    model_config = ConfigDict(from_attributes=True)


# --- Finding / Validation Schemas ---
class FindingBase(BaseModel):
    finding_title: str
    finding_type: str
    description: str
    confidence_score: float = 0.85
    validation_status: str = "Pending"
    investigator_notes: Optional[str] = None
    behavior_classification: Optional[str] = None
    classification_confidence: Optional[float] = None
    classification_reason: Optional[str] = None
    classification: Optional[Dict[str, Any]] = None


class FindingCreate(FindingBase):
    case_id: str
    event_id: Optional[str] = None


class FindingUpdate(BaseModel):
    validation_status: str  # "Accepted", "Rejected", "Modified"
    investigator_notes: Optional[str] = None
    finding_title: Optional[str] = None
    description: Optional[str] = None


class FindingResponse(FindingBase):
    finding_id: str
    case_id: str
    event_id: Optional[str] = None
    created_at: datetime
    linked_event: Optional[EventResponse] = None

    model_config = ConfigDict(from_attributes=True)


# --- Attack Node Schemas ---
class AttackNodeResponse(BaseModel):
    node_id: str
    case_id: str
    finding_id: Optional[str] = None
    mitre_technique: str
    stage_name: str
    stage_order: int
    description: str
    finding: Optional[FindingResponse] = None

    model_config = ConfigDict(from_attributes=True)


# --- Report Schemas ---
class ReportGenerateRequest(BaseModel):
    case_id: str
    report_name: str
    investigator_name: str = "Rohan Johny (Lead Forensic Examiner)"
    include_raw_hashes: bool = True
    executive_summary: Optional[str] = None


class ReportResponse(BaseModel):
    report_id: str
    case_id: str
    report_name: str
    integrity_hash: str
    status: str
    finalized_at: datetime
    encrypted_file_path: str

    model_config = ConfigDict(from_attributes=True)


class ReportDecryptResponse(BaseModel):
    report_id: str
    report_name: str
    plaintext_content: str
    integrity_hash: str
    is_tamper_free: bool
    verified_at: datetime


# --- AI Chat / Assistant Schemas ---
class CitationItem(BaseModel):
    event_id: str
    timestamp: str
    source_entity: str
    artifact_id: Optional[str] = None
    evidence_id: Optional[str] = None
    summary: str


class AIChatQuery(BaseModel):
    case_id: str
    query: str


class AIChatResponse(BaseModel):
    case_id: str
    query: str
    response: str
    citations: List[CitationItem]
    confidence_score: float
    analysis_type: str


# --- Audit Log Schema ---
class AuditLogResponse(BaseModel):
    log_id: str
    case_id: Optional[str] = None
    user_name: str
    action: str
    details: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
