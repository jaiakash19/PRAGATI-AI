import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from app import main as m


def admin_headers(client):
    r=client.post('/auth/login', json={'email':'admin@ipmprs.demo','password':'Demo@123'})
    assert r.status_code==200
    return {'Authorization':'Bearer '+r.json()['token']}


def test_activation_token_is_not_returned_and_is_one_time(monkeypatch):
    sent={}
    monkeypatch.setattr(m, 'send_activation', lambda email, token: sent.update(token=token))
    with TestClient(m.app) as client:
        with m.SessionLocal() as s:
            station=s.scalar(m.select(m.Station).order_by(m.Station.id))
            station_id=station.id
        response=client.post('/admin/provision', headers=admin_headers(client), json={'name':'Synthetic SI','email':'synthetic-si@example.test','rank':'SI','station_id':station_id})
        assert response.status_code==200
        assert 'token' not in response.json()
        token=sent['token']
        activated=client.post('/auth/activate', json={'token':token,'password':'Synthetic-Strong-Password-1'})
        assert activated.status_code==200
        replay=client.post('/auth/activate', json={'token':token,'password':'Synthetic-Strong-Password-2'})
        assert replay.status_code==400
        login=client.post('/auth/login', json={'email':'synthetic-si@example.test','password':'Synthetic-Strong-Password-1'})
        assert login.status_code==200


def test_non_admin_cannot_provision():
    with TestClient(m.app) as client:
        response=client.post('/admin/provision', json={'name':'Blocked','email':'blocked@example.test','rank':'SI','station_id':1})
        assert response.status_code in (401,403)
