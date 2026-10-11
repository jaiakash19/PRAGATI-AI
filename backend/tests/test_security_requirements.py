import hashlib
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app import main as m


def auth(client, email):
    r=client.post('/auth/login', json={'email': email, 'password': 'Demo@123'})
    assert r.status_code == 200
    return {'Authorization': 'Bearer ' + r.json()['token']}


def test_cross_station_record_id_cannot_bypass_membership():
    with m.SessionLocal() as s:
        user=s.scalar(m.select(m.User).where(m.User.email=='submitter@ipmprs.demo'))
        stations=s.scalars(m.select(m.Station).order_by(m.Station.id)).all()
        first, second=stations[0], stations[1]
        s.query(m.StationMembership).filter_by(user_id=user.id).update({'active':False})
        s.add(m.StationMembership(user_id=user.id, station_id=first.id))
        proposal=m.Proposal(reference='SEC-ISO-TEST', title='Synthetic station private record', summary='Synthetic record for station authorization testing.', category='Test', priority='Low', author_id=user.id, station_id=second.id)
        s.add(proposal); s.commit(); pid=proposal.id
    with TestClient(m.app) as client:
        assert client.get('/proposals/'+str(pid), headers=auth(client,'submitter@ipmprs.demo')).status_code == 403


def test_otp_wrong_code_is_single_use_and_success_cannot_replay(monkeypatch):
    monkeypatch.setattr(m, 'APP_ENV', 'production')
    sent={}
    monkeypatch.setattr(m, 'send_otp', lambda email, code: sent.update(code=code))
    with m.SessionLocal() as s:
        user=s.scalar(m.select(m.User).where(m.User.email=='admin@ipmprs.demo'))
        user.rank='SI'; user.email_verified=True; s.commit()
    with TestClient(m.app) as client:
        first=client.post('/auth/login', json={'email':'admin@ipmprs.demo','password':'Demo@123'})
        assert first.status_code == 200 and first.json()['otp_required'] is True
        challenge=first.json()['challenge_id']
        assert client.post('/auth/verify-otp', json={'challenge_id':challenge,'code':'000000'}).status_code == 401
        verified=client.post('/auth/verify-otp', json={'challenge_id':challenge,'code':sent['code']})
        assert verified.status_code == 200
        assert client.post('/auth/verify-otp', json={'challenge_id':challenge,'code':sent['code']}).status_code == 401
    monkeypatch.setattr(m, 'APP_ENV', 'development')
