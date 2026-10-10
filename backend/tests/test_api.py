import os
os.environ["DATABASE_URL"]="sqlite:///./test_ipmprs.db"
from fastapi.testclient import TestClient
try:
    from backend.app import main as main_module
except ModuleNotFoundError:  # supports local tests from the backend folder
    from app import main as main_module
app = main_module.app
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
