import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_STORAGE_DIR = DATA_DIR / "evidence_vault"
REPORT_STORAGE_DIR = DATA_DIR / "encrypted_reports"

DATA_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Default to SQLite for zero-friction local execution, switchable to PostgreSQL via env
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'forensight.db'}")

# Master Key for Module 7: Two-Key Security Architecture (protects Report Encryption Keys)
# In production, this can come from an HSM or environment secret.
MASTER_KEY_HEX = os.getenv(
    "FORENSIGHT_MASTER_KEY",
    "7f9a8b1c2d3e4f5061728394a5b6c7d8e9f0123456789abcdef0123456789abc"
)

API_TITLE = "Forensight AI - Digital Forensic Investigation Platform"
API_VERSION = "1.0.0"
API_PREFIX = "/api"
