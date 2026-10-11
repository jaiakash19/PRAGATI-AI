# IPMPRS — Intelligent Proposal Management & Precedent Retrieval System

IPMPRS manages police proposals from draft to evidence-backed closure, with role-enforced workflow and authorized historical-precedent retrieval.

## Prerequisites

- Windows: Docker Desktop with the WSL 2 backend, Git, Node.js 22+, and Python 3.12+.
- Docker Desktop is the supported production-like runtime. PostgreSQL is supplied by `pgvector/pgvector:pg16`.

## Configuration and launch

```powershell
Copy-Item .env.example .env
# Edit .env: set a unique POSTGRES_PASSWORD and a 32+ character SECRET_KEY.
docker compose up --build
```

The migration runs automatically before the API starts. By default open `http://localhost:5173`; the API health endpoint is `http://localhost:8000/health`. Override `WEB_PORT`, `API_PORT`, or `DB_PORT` when another local service already uses those ports. Production API documentation is intentionally disabled.

For a demo deployment only, set `DEMO_SEED=true` before the first start. Demo accounts all use `Demo@123`. Never use demo accounts or passwords in a real deployment.

## Development

SQLite is allowed only for local development/test. Production mode refuses to start without `DATABASE_URL` and a strong `SECRET_KEY`.

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:APP_ENV='development'
uvicorn app.main:app --reload

cd ..\frontend
npm ci
npm run dev
```

## Database, migrations, and pgvector

The first migration creates the schema and runs `CREATE EXTENSION IF NOT EXISTS vector` on PostgreSQL. It uses `vector(384)` for Sentence Transformers `all-MiniLM-L6-v2` embeddings.

```powershell
cd backend
$env:DATABASE_URL='postgresql+psycopg://ipmprs:password@localhost:5432/ipmprs'
alembic upgrade head
```

Semantic pgvector ranking runs only when the local embedding model can load and stored vectors exist. Otherwise the API explicitly returns deterministic lexical fallback; it never fabricates semantic scores.

Back up before schema changes:

```powershell
docker compose exec db pg_dump -U $env:POSTGRES_USER $env:POSTGRES_DB > ipmprs-backup.sql
Get-Content ipmprs-backup.sql | docker compose exec -T db psql -U $env:POSTGRES_USER $env:POSTGRES_DB
```

Do not remove the named Docker volumes (`postgres_data`, `uploads_data`) unless deliberately retiring all stored data.

## Verification

```powershell
python -m pytest backend\tests\test_api.py -q
npm --prefix frontend run build
docker compose config
docker compose ps
```

Tests cover login/dashboard and the four-role path: create → submit → review → recommend → approve → implementation → close → retrieve precedents.

## Security controls

- JWT sessions, PBKDF2 password hashes, backend-enforced roles and state transitions.
- Submitters are limited to their own/assigned proposals; documents use the same authorization gate.
- Assignments constrain officers when a proposal has explicit assignees.
- Upload allow-list, 10 MB cap, normalized filenames, SHA-256 stored filenames, extraction error handling, and audit logging.
- Production blocks weak secrets and wildcard CORS; API responses set `nosniff`, anti-frame, and referrer headers.

For public deployment, add TLS termination, malware scanning/object storage for documents, monitoring, rate limiting, managed secret storage, scheduled backup/restore drills, and an independent security assessment.


## Digitize case files (OCR)

- Attach PDF, DOCX, TXT, or photo/scan formats JPG/JPEG, PNG, WEBP, TIFF and BMP from a proposal. Upload limit is 10 MB.
- The original file bytes are stored in the database in the documents.content_blob field and also persisted in the uploads volume for compatibility and recovery. The database stores document type, extracted text, OCR status and metadata; uploads are linked to the proposal and audited.
- Search the document repository by filename, proposal reference or OCR-extracted text. Downloads return the exact original bytes from the database when available.
- Selectable PDF/DOCX/TXT text is extracted directly. Images and scanned PDF pages are processed with Tesseract OCR using English and Tamil language data. If your local non-Docker installation supports only English, install the Tesseract Tamil language pack too. OCR is attempted on PDF pages with little/no selectable text, up to 30 pages per upload. Make sure scans are upright and readable.
- OCR is an indexing aid, not certified transcription. Officers must verify extracted text against the original image before relying on it.
- Docker installs Tesseract. Local non-Docker setups must install the Tesseract engine separately and install requirements from backend/requirements.txt.
- Migration 0002_document_blob_and_ocr.py adds database binary storage and OCR metadata to existing installs. Back up the database before schema changes.
- The API test suite includes an upload, OCR-text-search, database-backed download, and document visibility test; OCR is mocked in tests so a local Tesseract binary is not required.


## Precedent Impact & Risk Intelligence

The proposal editor has a pre-submission precedent check, and every proposal detail page shows an evidence brief before review/approval. It compares positive and adverse historical records, flags contradictory precedent, lists recurring concerns from recorded observations/reviews, highlights missing recorded outcomes, and presents checks for the authorised officer. These are transparent heuristic screening cues, not a calibrated risk probability or an automatic approval/rejection decision.

Existing or imported proposals can be batch-indexed by an Admin from Precedent Search using the Reindex historical archive button. It embeds title, summary, category, decision, observations, outcomes and extracted document text. Newly created proposals, workflow decisions and implementation updates also refresh their embedding. If the local Sentence Transformers model cannot be downloaded/loaded, precedent retrieval uses a labelled lexical fallback.


## Structured decision and sanction history

- Workflow actions automatically create structured Decision, Observation or Modification records alongside the review and audit log.
- Approving Officers/Admins can record sanctions with rationale/conditions, reference/order number, optional amount/currency and effective date. The API prevents sanctions before approval.
- Implementation milestones are captured as structured Outcome records and added to precedent embeddings and keyword fallback.
- Admins/Approving Officers can explicitly publish a reviewed or completed proposal to the institutional precedent catalogue. Submitter searches include their own/assigned records plus published institutional precedents; reviewer and decision roles can search across departments according to their role.
- New-proposal precedent suggestions refresh automatically while the title, summary, category or priority is edited (debounced to avoid sending a request for every keystroke). Proposal detail pages load the impact brief automatically.
- Migration 0003_structured_decisions.py adds the structured records table and curated-publication flag to existing databases.
