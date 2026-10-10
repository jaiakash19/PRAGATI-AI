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

The migration runs automatically before the API starts. Open `http://localhost:5173`; the API health endpoint is `http://localhost:8000/health`. Production API documentation is intentionally disabled.

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
