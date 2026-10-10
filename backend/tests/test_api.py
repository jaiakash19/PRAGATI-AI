import os
os.environ["DATABASE_URL"]="sqlite:///./test_ipmprs.db"
from fastapi.testclient import TestClient
from backend.app.main import app
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
