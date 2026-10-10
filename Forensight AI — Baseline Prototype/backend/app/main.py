import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.core.config import API_TITLE, API_VERSION, API_PREFIX
from app.core.database import engine, Base, SessionLocal
from app.models import models
from app.sample_data.operation_blackout import seed_operation_blackout

from app.api.cases import router as cases_router
from app.api.evidence import router as evidence_router
from app.api.timeline import router as timeline_router
from app.api.findings import router as findings_router
from app.api.attack_path import router as attack_path_router
from app.api.ai import router as ai_router
from app.api.reports import router as reports_router
from app.api.auth import router as auth_router


def init_db():
    Base.metadata.create_all(bind=engine)
    from app.core.database import sync_database_schema
    sync_database_schema(engine)
    db = SessionLocal()
    try:
        case = seed_operation_blackout(db)
        print(f"[*] Forensight AI: Pre-loaded Demo Case: {case.case_number} ({case.case_name})")
    finally:
        db.close()

# Ensure tables are ready immediately upon import
init_db()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description="Forensight AI - Complete AI-Assisted Digital Forensic Investigation Platform API",
    lifespan=lifespan
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all 7 forensic module routers
app.include_router(cases_router, prefix=API_PREFIX)
app.include_router(evidence_router, prefix=API_PREFIX)
app.include_router(timeline_router, prefix=API_PREFIX)
app.include_router(findings_router, prefix=API_PREFIX)
app.include_router(attack_path_router, prefix=API_PREFIX)
app.include_router(ai_router, prefix=API_PREFIX)
app.include_router(reports_router, prefix=API_PREFIX)
app.include_router(auth_router, prefix=API_PREFIX)


@app.get("/api/system/tools")
def get_system_tools():
    """Returns detected forensic tool statuses from M1 client."""
    from app.forensics.m1_client import M1Client
    return {"tools": M1Client.get_tool_status()}


@app.get("/")
def root():
    return {
        "platform": "Forensight AI",
        "status": "OPERATIONAL",
        "modules_active": [
            "Module 1: Case & Evidence Management",
            "Module 2: Forensic Artifact Extraction & Normalization",
            "Module 3: Forensic Analysis & Correlation",
            "Module 4: AI Investigation Assistant (RAG)",
            "Module 5: Attack-Path Reconstruction & Validation",
            "Module 6: Professional Report Generation",
            "Module 7: Secure Report Storage (Two-Key AES-256-GCM Vault)"
        ],
        "docs_url": "/docs"
    }


@app.post("/api/system/seed")
def reseed_database():
    """Manually resets/reseeds the 'Operation Blackout' forensic dataset."""
    db = SessionLocal()
    try:
        case = seed_operation_blackout(db)
        return {
            "status": "SUCCESS",
            "case_id": case.case_id,
            "case_number": case.case_number,
            "case_name": case.case_name
        }
    finally:
        db.close()


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
