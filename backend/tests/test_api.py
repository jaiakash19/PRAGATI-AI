import os
import sys
from pathlib import Path
import pytest

TEST_DB = Path(__file__).resolve().parent / "test_ipmprs.db"
if TEST_DB.exists(): TEST_DB.unlink()
os.environ["DATABASE_URL"]="sqlite:///" + TEST_DB.as_posix()
from fastapi.testclient import TestClient

# Resolve backend/app regardless of whether pytest is invoked from repo root
# (README CI command) or from the backend folder (developer command).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import main as main_module
app = main_module.app

@pytest.fixture(autouse=True)
def disable_embedding_model_downloads(monkeypatch):
    # Keep API tests fast and deterministic; semantic-vector retrieval needs a separate model-enabled test environment.
    monkeypatch.setattr(main_module, "embedding", lambda text: None)
def test_login_and_dashboard():
    with TestClient(app) as c:
        r=c.post("/auth/login",json={"email":"admin@ipmprs.demo","password":"Demo@123"});assert r.status_code==200
        assert c.get("/dashboard",headers={"Authorization":"Bearer "+r.json()["token"]}).status_code==200

def test_proposal_to_closure_workflow():
    with TestClient(app) as c:
        def auth(email):
            r=c.post("/auth/login",json={"email":email,"password":"Demo@123"})
            return {"Authorization":"Bearer "+r.json()["token"]}
        submitter=auth("submitter@ipmprs.demo")
        created=c.post("/proposals",headers=submitter,json={"title":"Secure evidence tablet pilot","summary":"Controlled pilot for digital evidence capture by patrol teams.","category":"Technology","priority":"High"})
        assert created.status_code==200
        pid=created.json()["id"]
        for headers,action in [(submitter,"submit"),(auth("reviewer@ipmprs.demo"),"review"),(auth("reviewer@ipmprs.demo"),"recommend"),(auth("approver@ipmprs.demo"),"approve")]:
            assert c.post(f"/proposals/{pid}/action",headers=headers,json={"action":action,"reason":"Recorded workflow decision."}).status_code==200
        closed=c.post(f"/proposals/{pid}/implementation",headers=auth("implementation@ipmprs.demo"),json={"progress":100,"milestone":"Closure","evidence":"Acceptance evidence recorded."})
        assert closed.json()["status"]=="Closed"
        assert c.get(f"/proposals/{pid}/precedents",headers=auth("admin@ipmprs.demo")).status_code==200

def test_forbidden_cross_submitter_access_and_invalid_transition():
    with TestClient(app) as c:
        def auth(email):
            return {"Authorization":"Bearer "+c.post("/auth/login",json={"email":email,"password":"Demo@123"}).json()["token"]}
        owner=auth("submitter@ipmprs.demo")
        proposal=c.post("/proposals",headers=owner,json={"title":"Restricted draft proposal","summary":"A proposal used to verify authorization boundaries.","category":"Training","priority":"Low"}).json()
        # A submitter cannot approve, and an approving officer cannot approve a draft.
        assert c.post(f"/proposals/{proposal['id']}/action",headers=owner,json={"action":"approve","reason":"Unauthorized action"}).status_code==403
        assert c.post(f"/proposals/{proposal['id']}/action",headers=auth("approver@ipmprs.demo"),json={"action":"approve","reason":"Wrong state"}).status_code==409


def test_case_file_photo_is_saved_and_ocr_text_is_searchable(monkeypatch):
    # API/database integration test; mock OCR so CI does not need Tesseract.
    monkeypatch.setattr(
        main_module,
        "extract_document_text",
        lambda raw, content_type: ("case number PX-104 evidence timeline", "ocr_processed"),
    )
    with TestClient(app) as c:
        login = c.post("/auth/login", json={"email":"submitter@ipmprs.demo","password":"Demo@123"})
        assert login.status_code == 200
        headers = {"Authorization":"Bearer "+login.json()["token"]}
        created = c.post("/proposals", headers=headers, json={
            "title":"Photo case file persistence test",
            "summary":"Verify that scanned case photos are stored in the database.",
            "category":"Technology",
            "priority":"Medium"
        })
        assert created.status_code == 200
        pid = created.json()["id"]
        original = b"simulated-image-bytes-for-test"
        uploaded = c.post(
            f"/proposals/{pid}/documents",
            headers=headers,
            data={"document_type":"Photo/Scan"},
            files={"file":("case-scan.jpg", original, "image/jpeg")},
        )
        assert uploaded.status_code == 200, uploaded.text
        result = uploaded.json()
        assert result["saved_in_database"] is True
        assert result["searchable"] is True
        assert result["extracted_characters"] > 10
        details = c.get(f"/proposals/{pid}", headers=headers)
        assert details.status_code == 200
        doc = details.json()["documents"][0]
        assert doc["document_type"] == "Photo/Scan"
        assert doc["ocr_status"] == "ocr_processed"
        assert doc["extracted_text_length"] > 10
        matches = c.get("/documents", headers=headers, params={"q":"evidence timeline"})
        assert matches.status_code == 200
        assert any(d["id"] == result["id"] for d in matches.json())
        downloaded = c.get(f"/documents/{result['id']}/download", headers=headers)
        assert downloaded.status_code == 200
        assert downloaded.content == original


def test_submitter_cannot_list_another_submitters_documents():
    with TestClient(app) as c:
        def auth(email):
            response = c.post("/auth/login", json={"email":email,"password":"Demo@123"})
            assert response.status_code == 200
            return {"Authorization":"Bearer "+response.json()["token"]}
        owner = auth("submitter@ipmprs.demo")
        created = c.post("/proposals", headers=owner, json={
            "title":"Private case document fixture",
            "summary":"A proposal used for validating private case file listing.",
            "category":"Training","priority":"Low"
        })
        assert created.status_code == 200
        proposal = created.json()
        admin = auth("admin@ipmprs.demo")
        second = c.post("/users", headers=admin, json={
            "name":"Second Submitter","email":"second-submitter@ipmprs.demo",
            "role":"Submitter","password":"Demo@123","active":True
        })
        assert second.status_code in (200, 409)
        outsider = auth("second-submitter@ipmprs.demo")
        assert c.get("/documents",headers=outsider,params={"q":"case"}).json() == []
        assert c.get(f"/proposals/{proposal['id']}",headers=outsider).status_code == 403


def test_precedent_intelligence_includes_rejected_historical_records():
    with TestClient(app) as c:
        def auth(email):
            response=c.post("/auth/login",json={"email":email,"password":"Demo@123"})
            assert response.status_code==200
            return {"Authorization":"Bearer "+response.json()["token"]}
        submitter=auth("submitter@ipmprs.demo")
        reviewer=auth("reviewer@ipmprs.demo")
        approver=auth("approver@ipmprs.demo")
        old=c.post("/proposals",headers=submitter,json={
            "title":"Digital evidence camera procurement pilot",
            "summary":"A pilot to procure digital evidence cameras for patrol units and record chain of custody.",
            "category":"Technology","priority":"High"
        })
        assert old.status_code==200
        rejected=old.json()
        assert c.post(f"/proposals/{rejected['id']}/action",headers=submitter,json={"action":"submit","reason":"Submit for review."}).status_code==200
        assert c.post(f"/proposals/{rejected['id']}/action",headers=reviewer,json={"action":"review","reason":"Assess feasibility."}).status_code==200
        assert c.post(f"/proposals/{rejected['id']}/action",headers=reviewer,json={"action":"recommend","reason":"Recommend for decision."}).status_code==200
        assert c.post(f"/proposals/{rejected['id']}/action",headers=approver,json={"action":"reject","reason":"Prior pilot lacked budget and privacy controls."}).status_code==200
        preview=c.post("/precedents/preview",headers=submitter,json={
            "title":"Digital evidence camera procurement pilot phase two",
            "summary":"Procure evidence cameras for patrol teams and include budget and privacy controls.",
            "category":"Technology","priority":"High"
        })
        assert preview.status_code==200, preview.text
        data=preview.json()
        assert any(x["id"]==rejected["id"] and x["status"]=="Rejected" for x in data["matches"])
        assert any(x["reference"]==rejected["reference"] for x in data["impact_brief"]["adverse_precedents"])
        assert "not a calibrated risk probability" in data["impact_brief"]["disclaimer"]


def test_admin_can_reindex_historical_proposal_archive(monkeypatch):
    class FakeEmbeddingModel:
        def encode(self, texts, normalize_embeddings=True, batch_size=16):
            return [[0.0] * 384 for _ in texts]
    monkeypatch.setattr(main_module, "_embedding_model", FakeEmbeddingModel())
    with TestClient(app) as c:
        login=c.post("/auth/login",json={"email":"admin@ipmprs.demo","password":"Demo@123"})
        assert login.status_code==200
        headers={"Authorization":"Bearer "+login.json()["token"]}
        response=c.post("/admin/reindex-embeddings",headers=headers)
        assert response.status_code==200, response.text
        data=response.json()
        assert data["indexed"] == data["total"]
        assert data["dimensions"] == 384


def test_structured_sanction_history_is_saved_and_retrievable():
    with TestClient(app) as c:
        def auth(email):
            response=c.post("/auth/login",json={"email":email,"password":"Demo@123"})
            assert response.status_code==200
            return {"Authorization":"Bearer "+response.json()["token"]}
        submitter=auth("submitter@ipmprs.demo")
        reviewer=auth("reviewer@ipmprs.demo")
        approver=auth("approver@ipmprs.demo")
        created=c.post("/proposals",headers=submitter,json={
            "title":"Digital evidence storage expansion",
            "summary":"Expand digital evidence storage capacity with encryption, audit and retention controls.",
            "category":"Technology","priority":"High"
        })
        assert created.status_code==200
        p=created.json()
        for headers,action in [(submitter,"submit"),(reviewer,"review"),(reviewer,"recommend"),(approver,"approve")]:
            response=c.post(f"/proposals/{p['id']}/action",headers=headers,json={"action":action,"reason":"Review record for structured audit."})
            assert response.status_code==200,response.text
        sanction=c.post(f"/proposals/{p['id']}/decision-records",headers=approver,json={
            "record_type":"Sanction","title":"Phase I administrative sanction",
            "details":"Approved for phase I subject to quarterly expenditure review and retention compliance.",
            "reference_number":"SAN-TEST-2026-01","amount":125000.50,"currency":"INR",
            "effective_date":"2026-10-15T00:00:00Z"
        })
        assert sanction.status_code==200,sanction.text
        assert sanction.json()["record_type"]=="Sanction"
        assert sanction.json()["reference_number"]=="SAN-TEST-2026-01"
        assert sanction.json()["amount"]==125000.50
        assert c.post(f"/proposals/{p['id']}/decision-records",headers=submitter,json={
            "record_type":"Sanction","title":"Unauthorised sanction","details":"Should not be allowed."
        }).status_code==403
        detail=c.get(f"/proposals/{p['id']}",headers=submitter)
        assert detail.status_code==200
        kinds={r["record_type"] for r in detail.json()["decision_records"]}
        assert {"Decision","Observation","Sanction"}.issubset(kinds)
        assert any(r["reference_number"]=="SAN-TEST-2026-01" for r in detail.json()["decision_records"])
        preview=c.post("/precedents/preview",headers=submitter,json={
            "title":"Digital evidence storage expansion",
            "summary":"Expand digital evidence storage capacity with encryption, audit and retention controls.",
            "category":"Technology","priority":"High"
        })
        assert preview.status_code==200
        assert any(s["reference_number"]=="SAN-TEST-2026-01" for s in preview.json()["impact_brief"]["sanctions"])


def test_submitter_precedent_scope_respects_curated_publication():
    with TestClient(app) as c:
        def auth(email):
            response=c.post("/auth/login",json={"email":email,"password":"Demo@123"})
            assert response.status_code==200
            return {"Authorization":"Bearer "+response.json()["token"]}
        submitter=auth("submitter@ipmprs.demo")
        admin=auth("admin@ipmprs.demo")
        token=os.urandom(5).hex()
        with main_module.SessionLocal() as session:
            admin_user=session.scalar(main_module.select(main_module.User).where(main_module.User.email=="admin@ipmprs.demo"))
            remote=main_module.Department(name="Cross Department Test "+token)
            session.add(remote);session.flush()
            private=main_module.Proposal(reference="PRIV-"+token,title="Restricted spectral bridge telemetry",
                summary="Confidential tungsten relay architecture for limited engineering review.",category="Technology",
                priority="High",status="Closed",author_id=admin_user.id,department_id=remote.id,
                decision="Approved",observations="Restricted design details.",outcome="Completed",precedent_visible=False)
            published=main_module.Proposal(reference="PUB-"+token,title="Institutional radio equipment modernisation",
                summary="Cross-department radio equipment modernisation and maintenance planning.",category="Technology",
                priority="Medium",status="Closed",author_id=admin_user.id,department_id=remote.id,
                decision="Approved",observations="Standard procurement controls.",outcome="Maintenance plan delivered.",precedent_visible=True)
            session.add_all([private,published]);session.commit()
            private_id,public_id=private.id,published.id
        private_query=c.post("/precedents/preview",headers=submitter,json={
            "title":"Restricted spectral bridge telemetry",
            "summary":"Confidential tungsten relay architecture for limited engineering review.",
            "category":"Technology","priority":"High"
        })
        assert private_query.status_code==200
        assert all(x["id"]!=private_id for x in private_query.json()["matches"])
        public_query=c.post("/precedents/preview",headers=submitter,json={
            "title":"Institutional radio equipment modernisation",
            "summary":"Cross-department radio equipment modernisation and maintenance planning.",
            "category":"Technology","priority":"Medium"
        })
        assert public_query.status_code==200
        assert any(x["id"]==public_id for x in public_query.json()["matches"])
        staff_query=c.post("/precedents/preview",headers=admin,json={
            "title":"Restricted spectral bridge telemetry",
            "summary":"Confidential tungsten relay architecture for limited engineering review.",
            "category":"Technology","priority":"High"
        })
        assert staff_query.status_code==200
        assert any(x["id"]==private_id for x in staff_query.json()["matches"])


def test_only_authorised_officers_can_publish_precedents():
    with TestClient(app) as c:
        def auth(email):
            response=c.post("/auth/login",json={"email":email,"password":"Demo@123"})
            assert response.status_code==200
            return {"Authorization":"Bearer "+response.json()["token"]}
        submitter=auth("submitter@ipmprs.demo")
        approver=auth("approver@ipmprs.demo")
        draft=c.post("/proposals",headers=submitter,json={
            "title":"Precedent publication access test",
            "summary":"Test who can publish a proposal as an institutional precedent.",
            "category":"Training","priority":"Low"
        }).json()
        assert c.post(f"/proposals/{draft['id']}/precedent-visibility",headers=submitter,json={"visible":True}).status_code==403
        assert c.post(f"/proposals/{draft['id']}/precedent-visibility",headers=approver,json={"visible":True}).status_code==409
