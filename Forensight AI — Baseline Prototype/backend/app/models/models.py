import re
import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column, String, Text, Float, Integer, DateTime, ForeignKey, JSON, LargeBinary
)
from sqlalchemy.orm import relationship
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    user_id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), default="Investigator")  # "Admin", "Investigator"
    created_at = Column(DateTime, default=datetime.utcnow)

    cases = relationship("Case", back_populates="user", cascade="all, delete-orphan")


class Case(Base):
    __tablename__ = "cases"

    case_id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.user_id"), nullable=False)
    case_number = Column(String(50), unique=True, nullable=False, index=True)
    case_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), default="Active")  # "Active", "Under Investigation", "Closed"
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="cases")
    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="case", cascade="all, delete-orphan")
    attack_nodes = relationship("AttackNode", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    evidence_id = Column(String(100), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    source_name = Column(String(255), nullable=False)
    evidence_type = Column(String(50), nullable=False)  # "DISK_IMAGE", "MEMORY_DUMP", "EVTX", "REGISTRY", "PCAP"
    storage_path = Column(String(500), nullable=False)
    hash_sha256 = Column(String(64), nullable=False)
    hash_sha1 = Column(String(40), nullable=True)
    hash_md5 = Column(String(32), nullable=True)
    byte_size = Column(String(50), nullable=True)
    processing_status = Column(String(50), default="PENDING")  # "PENDING", "EXTRACTING", "NORMALIZING", "INGESTING", "ANALYZING", "COMPLETED", "FAILED"
    processing_error = Column(Text, nullable=True)
    ingested_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="evidence_items")
    artifacts = relationship("Artifact", back_populates="evidence", cascade="all, delete-orphan")


class Artifact(Base):
    __tablename__ = "artifacts"

    artifact_id = Column(String(100), primary_key=True, default=generate_uuid)
    evidence_id = Column(String(100), ForeignKey("evidence.evidence_id"), nullable=False, index=True)
    artifact_type = Column(String(50), nullable=False)  # "LOG", "REGISTRY", "PROCESS", "NETWORK", "FILESYSTEM"
    parser_used = Column(String(100), nullable=False)
    raw_data = Column(JSON, nullable=True)
    extracted_at = Column(DateTime, default=datetime.utcnow)

    evidence = relationship("Evidence", back_populates="artifacts")
    events = relationship("Event", back_populates="artifact", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "events"

    event_id = Column(String(100), primary_key=True, default=generate_uuid)
    source_event_id = Column(String(100), nullable=True, index=True)
    artifact_id = Column(String(100), ForeignKey("artifacts.artifact_id"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=True, index=True)  # Normalized to UTC, nullable for forensic integrity
    event_type = Column(String(100), nullable=False, index=True)
    source_entity = Column(String(150), nullable=False)
    user_account = Column(String(100), nullable=True)
    host_ip = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    is_anomalous = Column(Integer, default=0)  # 0 or 1
    anomaly_score = Column(Float, default=0.0)

    artifact = relationship("Artifact", back_populates="events")
    findings = relationship("Finding", back_populates="event")


class Finding(Base):
    __tablename__ = "findings"

    finding_id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    event_id = Column(String(100), ForeignKey("events.event_id"), nullable=True, index=True)
    finding_title = Column(String(255), nullable=False)
    finding_type = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    confidence_score = Column(Float, default=0.85)
    validation_status = Column(String(30), default="Pending")  # "Pending", "Accepted", "Rejected", "Modified"
    investigator_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="findings")
    event = relationship("Event", back_populates="findings")
    attack_nodes = relationship("AttackNode", back_populates="finding")

    @property
    def behavior_classification(self) -> Optional[str]:
        if getattr(self, "_behavior_classification", None) is not None:
            return self._behavior_classification
        ev = self.event or getattr(self, "_mock_event", None)
        if ev:
            from app.ai.evidence_classifier import EvidenceClassificationEngine
            details = getattr(ev, "details", {})
            details = details if isinstance(details, dict) else {}
            return EvidenceClassificationEngine.classify_event(
                getattr(ev, "event_type", ""), details
            ).get("primary_category")
        if self.description:
            match = re.search(r"Behavior Classification:\s*([A-Z_]+)", self.description)
            if match:
                return match.group(1).strip()
        return None

    @behavior_classification.setter
    def behavior_classification(self, value: Optional[str]) -> None:
        self._behavior_classification = value

    @property
    def classification_confidence(self) -> Optional[float]:
        if getattr(self, "_classification_confidence", None) is not None:
            return self._classification_confidence
        ev = self.event or getattr(self, "_mock_event", None)
        if ev:
            from app.ai.evidence_classifier import EvidenceClassificationEngine
            details = getattr(ev, "details", {})
            details = details if isinstance(details, dict) else {}
            return EvidenceClassificationEngine.classify_event(
                getattr(ev, "event_type", ""), details
            ).get("confidence")
        if self.description:
            match = re.search(r"Classification Confidence:\s*([0-9.]+)", self.description)
            if match:
                try:
                    return float(match.group(1).strip())
                except ValueError:
                    pass
        return None

    @classification_confidence.setter
    def classification_confidence(self, value: Optional[float]) -> None:
        self._classification_confidence = value

    @property
    def classification_reason(self) -> Optional[str]:
        if getattr(self, "_classification_reason", None) is not None:
            return self._classification_reason
        ev = self.event or getattr(self, "_mock_event", None)
        if ev:
            from app.ai.evidence_classifier import EvidenceClassificationEngine
            details = getattr(ev, "details", {})
            details = details if isinstance(details, dict) else {}
            classification = EvidenceClassificationEngine.classify_event(
                getattr(ev, "event_type", ""), details
            )
            reasons = classification.get("reasons", [])
            return reasons[-1] if reasons else None
        if self.description:
            match = re.search(r"Classification Reason:\s*([^\n\r]+)", self.description)
            if match:
                return match.group(1).strip()
        return None

    @classification_reason.setter
    def classification_reason(self, value: Optional[str]) -> None:
        self._classification_reason = value

    @property
    def classification(self) -> Optional[Dict[str, Any]]:
        if getattr(self, "_classification", None) is not None:
            return self._classification
        ev = self.event or getattr(self, "_mock_event", None)
        if ev:
            from app.ai.evidence_classifier import EvidenceClassificationEngine
            details = getattr(ev, "details", {})
            details = details if isinstance(details, dict) else {}
            return EvidenceClassificationEngine.classify_event(
                getattr(ev, "event_type", ""), details
            )
        return None

    @classification.setter
    def classification(self, value: Optional[Dict[str, Any]]) -> None:
        self._classification = value


class AttackNode(Base):
    __tablename__ = "attack_nodes"

    node_id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.finding_id"), nullable=True, index=True)
    mitre_technique = Column(String(100), nullable=False)
    stage_name = Column(String(100), nullable=False)  # e.g., "Initial Access", "Execution", "Persistence"
    stage_order = Column(Integer, nullable=False)
    description = Column(Text, nullable=False)

    case = relationship("Case", back_populates="attack_nodes")
    finding = relationship("Finding", back_populates="attack_nodes")


class Report(Base):
    __tablename__ = "reports"

    report_id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    report_name = Column(String(255), nullable=False)
    integrity_hash = Column(String(64), nullable=False)  # Plaintext SHA-256
    encrypted_file_path = Column(String(500), nullable=False)
    encrypted_rek = Column(LargeBinary, nullable=False)  # REK wrapped with MK via AES-256-GCM
    status = Column(String(30), default="Final")  # "Draft", "Final"
    finalized_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), nullable=True, index=True)
    user_name = Column(String(100), default="Investigator")
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
