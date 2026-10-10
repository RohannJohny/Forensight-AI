# Forensight AI — Baseline Prototype

Forensight AI is an intelligent digital forensics investigation platform designed to streamline evidence analysis, anomaly detection, MITRE ATT&CK mapping, timeline reconstruction, and cryptographically verified dossier generation.

---

## 🏛️ System Architecture

- **Backend**: FastAPI (Python 3.10+), SQLite database, Pydantic v2 schemas, cryptographic verification engine, AI/heuristic anomaly detection & MITRE ATT&CK mapping.
- **Frontend**: React 18, Vite, Lucide Icons, responsive dark-themed forensic analyst dashboard.

---

## 🚀 Quick Start

### 1. Backend Setup

```bash
cd backend

# Create and activate virtual environment (optional but recommended)
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the API server
uvicorn app.main:app --reload --port 8000
```

- API Docs (Swagger): [http://localhost:8000/docs](http://localhost:8000/docs)
- Interactive ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### 2. Frontend Setup

```bash
cd frontend

# Install node dependencies
npm install

# Start Vite development server
npm run dev
```

- Frontend App: [http://localhost:5173](http://localhost:5173)

---

## 📂 Project Structure

```
Forensight AI — Baseline Prototype/
├── backend/
│   ├── app/
│   │   ├── ai/              # AI assistant, anomaly detection & MITRE mapping
│   │   ├── api/             # REST endpoints (cases, evidence, timeline, findings, reports)
│   │   ├── core/            # Config, database, crypto hashing & verification
│   │   ├── forensics/       # Evidentiary parsing & extraction logic
│   │   ├── models/          # SQLAlchemy DB models
│   │   ├── sample_data/     # Demo cases & pre-seeded forensic datasets
│   │   └── schemas/         # Pydantic schemas
│   ├── data/
│   │   ├── forensight.db    # Baseline SQLite forensic database
│   │   ├── evidence_vault/  # Storage for ingested forensic artifacts
│   │   └── encrypted_reports/ # Tamper-evident generated dossiers
│   ├── tests/               # Unit and integration test suites
│   └── requirements.txt     # Python dependencies
└── frontend/
    ├── public/              # Static assets & icons
    ├── src/
    │   ├── assets/          # Application graphics
    │   ├── components/      # UI components (Sidebar, TopBar, etc.)
    │   ├── services/        # Backend API service bindings
    │   └── views/           # Investigative dashboard views
    ├── package.json         # Node dependencies & build scripts
    └── vite.config.js       # Vite configuration
```

---

## 🔒 Security & Forensic Integrity
- SHA-256 evidence chain of custody verification.
- Tamper-evident dossier generation with HMAC cryptographic validation.
- Role-based operational access and immutable audit logging.
