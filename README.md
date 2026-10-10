# Forensight AI

> **Next-Generation Multi-Agent AI Digital Forensics & Incident Response Platform**

Forensight AI is an end-to-end, intelligent digital forensics platform engineered for forensic examiners, incident responders, and cyber investigators. It automates evidence classification, multi-tool forensic ingestion, timeline correlation, anomaly detection, MITRE ATT&CK mapping, and cryptographically verified dossier generation.

---

## 🏛️ Platform Architecture

The repository contains the integrated modules comprising the complete Forensight AI ecosystem:

```
Forensight-AI/
├── Forensight AI — Baseline Prototype/  # Core Full-Stack Application
│   ├── backend/                         # FastAPI (Python 3.10+) Backend API
│   │   ├── app/
│   │   │   ├── ai/                      # RAG assistant, classifier & anomaly engine
│   │   │   ├── api/                     # REST endpoints (cases, evidence, findings, reports)
│   │   │   ├── core/                    # Security, cryptographic verification, config
│   │   │   ├── forensics/               # Pipeline ingestion & semantics service
│   │   │   └── models/                  # SQLAlchemy ORM models & database
│   │   └── tests/                       # Integration & forensic test suites
│   ├── frontend/                        # React 18 + Vite Forensic Dashboard UI
│   │   └── src/
│   │       ├── components/              # Sidebar, TopBar, Examiner Notes, Search
│   │       ├── views/                   # Dashboard, Timeline, Attack Path, Explorer, etc.
│   │       └── services/                # Backend API client
│   ├── schemas/                         # Shared Pydantic data schemas
│   └── start_servers.bat                # One-click service launcher
│
├── forensight-final/                    # Ingestion & Normalization Engine (M1 Pipeline)
│   ├── app/
│   │   ├── cli.py                       # CLI routing & forensic processor runner
│   │   ├── parsers/                     # Autopsy, Plaso, Volatility 3 output parsers
│   │   └── tools/                       # Tool detection & routing logic
│   └── config/                          # Tool configuration definitions
│
├── abel_tom_project.pdf                 # Project architecture & documentation dossier
└── .gitignore                           # Repository ignore configuration
```

---

## ✨ Key Capabilities

1. **Automated Evidence Intake & Tool Routing**: Intelligent classification of forensic disk images (`.E01`, `.raw`), memory dumps (`.mem`), packet captures (`.pcapng`), and Windows event logs (`.evtx`).
2. **Tri-Engine Forensic Processing**: Deep integration with industry-standard forensic tools:
   - **Autopsy / The Sleuth Kit** for disk artifacts and file analysis.
   - **Plaso / log2timeline** for comprehensive super-timeline event extraction.
   - **Volatility 3** for volatile memory introspection.
3. **Common 17-Field Normalization**: Unifies disparate forensic outputs into a strictly typed common forensic event schema for cross-source correlation.
4. **Interactive Forensics Dashboard**:
   - Super-timeline reconstruction with temporal filtering and multi-attribute search.
   - Interactive MITRE ATT&CK kill-chain and attack path graph visualization.
   - Real-time anomaly detection and risk scoring.
   - In-app examiner note-taking and case audit trails.
5. **Cryptographic Validation & Integrity**: SHA-256 evidence chain of custody, tamper-evident audit logs, and encrypted, digitally signed forensic dossiers.

---

## 🚀 Quick Start Guide

### Option 1: One-Click Launch (Windows)

Simply double-click:
```cmd
start_servers.bat
```
This automatically starts both the FastAPI backend on `http://localhost:8000` and the Vite React UI on `http://localhost:5173`, opening your default browser.

---

### Option 2: Manual Service Startup

#### 1. Backend Service
```bash
cd "Forensight AI — Baseline Prototype/backend"

# Create and activate Python virtual environment
python -m venv venv
.\venv\Scripts\activate   # On Windows
# source venv/bin/activate # On Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Start backend server
python -m uvicorn app.main:app --reload --port 8000
```
- **API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc Specifications**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

#### 2. Frontend Dashboard
```bash
cd "Forensight AI — Baseline Prototype/frontend"

# Install npm packages
npm install

# Run development server
npm run dev
```
- **Dashboard Interface**: [http://localhost:5173](http://localhost:5173)

---

## 🧪 Running Tests

To execute the automated backend integration and forensic unit test suite:

```bash
cd "Forensight AI — Baseline Prototype/backend"
pytest
```

---

## 🔒 Security & Compliance

Forensight AI adheres to forensic standards:
- **Chain of Custody**: Cryptographic hashing (SHA-256) upon evidence intake.
- **Audit Logging**: Immutable, append-only logs for all examiner actions and AI inference runs.
- **Validation Gate**: Strict verification of data integrity before findings are certified in final reports.

---

## 📄 License & Attribution

Developed as part of the Forensight AI forensic intelligence research initiative.
