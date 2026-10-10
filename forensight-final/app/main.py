from __future__ import annotations

import tempfile
from pathlib import Path

try:
    from fastapi import FastAPI, File, HTTPException, UploadFile
    from fastapi.responses import JSONResponse
except ImportError:
    FastAPI = None

from app.evidence_identifier import identify_evidence
from app.input_router import classify_input
from app.pipeline import process_file, normalize_events
from app.tools.detector import tool_status

if FastAPI:
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI(title="Forensight AI - Forensic Evidence Intake & Normalization", version="5.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health():
        return {"status": "ok", "module": "Forensight AI - Ingestion, Extraction & Normalization"}

    @app.get("/tools")
    def tools():
        return {"tools": tool_status()}

    @app.post("/identify")
    async def identify_endpoint(file: UploadFile = File(...), kind: str = "auto"):
        suffix = Path(file.filename or "input.bin").suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(await file.read())
            temp_path = tmp.name
        try:
            res = identify_evidence(temp_path, requested_kind=kind)
            d = res.to_dict()
            d["filename"] = file.filename or d["filename"]
            return d
        finally:
            Path(temp_path).unlink(missing_ok=True)

    @app.post("/route")
    async def route_endpoint(file: UploadFile = File(...), kind: str = "auto"):
        suffix = Path(file.filename or "input.bin").suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(await file.read())
            temp_path = tmp.name
        try:
            r = classify_input(temp_path, requested_kind=kind)
            return {
                "kind": r.kind,
                "primary_tools": list(r.primary_tools),
                "description": r.description,
                "reason": r.reason,
                "classification": r.classification.to_dict() if r.classification else None,
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            Path(temp_path).unlink(missing_ok=True)

    @app.post("/process")
    async def process_endpoint(file: UploadFile = File(...), case_id: str = "case-upload", kind: str = "auto", timeline: bool = True):
        suffix = Path(file.filename or "input.bin").suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(await file.read())
            temp_path = tmp.name
        try:
            result = process_file(temp_path, output_dir=f"cases/{case_id}", kind=kind, timeline=timeline)
            return JSONResponse(result)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            Path(temp_path).unlink(missing_ok=True)

    @app.post("/process-path")
    async def process_path_endpoint(payload: dict):
        file_path = payload.get("file_path")
        if not file_path or not Path(file_path).exists():
            raise HTTPException(status_code=400, detail="file_path does not exist or was not provided")
        case_id = payload.get("case_id", "case-upload")
        kind = payload.get("kind", "auto")
        timeline = payload.get("timeline", True)
        output_dir = payload.get("output_dir", f"cases/{case_id}")
        try:
            result = process_file(file_path, output_dir=output_dir, kind=kind, timeline=timeline)
            return JSONResponse(result)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/normalize")
    def normalize_endpoint(payload: dict):
        raw = payload.get("events")
        if not isinstance(raw, list):
            raise HTTPException(status_code=400, detail="events must be an array")
        source = payload.get("source", "API")
        return {"events": [e.to_dict() for e in normalize_events([x for x in raw if isinstance(x, dict)], source=source)]}
else:
    app = None
