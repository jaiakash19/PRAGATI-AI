# IPMPRS — Intelligent Proposal Management & Precedent Retrieval System

Government police administration portal for proposal lifecycle, precedent retrieval, review, implementation, and closure.

## Start

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:5173`; FastAPI documentation is available at `http://localhost:8000/docs`.

Demo password for each account: `Demo@123`.

| Role | Account |
| --- | --- |
| Admin | admin@ipmprs.demo |
| Submitter | submitter@ipmprs.demo |
| Reviewer | reviewer@ipmprs.demo |
| Approving Officer | approver@ipmprs.demo |
| Implementation Officer | implementation@ipmprs.demo |

## Local development

```bash
cd backend; python -m venv .venv; .venv\Scripts\pip install -r requirements.txt; uvicorn app.main:app --reload
cd frontend; npm install; npm run dev
```

PostgreSQL with pgvector is the deployment database. SQLite is a development/test fallback. API startup creates normalized tables and demo records; add Alembic migrations before a production deployment.

## Safeguards

- JWT authentication and backend role enforcement.
- Upload type/size validation, content-addressed filenames, and audit logging.
- Precedent search returns only persisted authorized completed records and never fabricates decisions. Lexical search is the current available fallback for unavailable embeddings.
- Run API test: `cd backend; pytest`.
