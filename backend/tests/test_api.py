import os
os.environ["DATABASE_URL"]="sqlite:///./test_ipmprs.db"
from fastapi.testclient import TestClient
try:
    from backend.app.main import app
except ModuleNotFoundError:  # supports `cd backend; pytest` from the README
    from app.main import app
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
