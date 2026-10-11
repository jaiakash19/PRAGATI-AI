from app import main as m


def auth(client, email):
    response = client.post('/auth/login', json={'email': email, 'password': 'Demo@123'})
    assert response.status_code == 200
    return {'Authorization': 'Bearer ' + response.json()['token']}


def test_station_directory_and_manager_authorization():
    with m.SessionLocal() as s:
        station = m.Station(code='TEST-AUTH', name='Test Station', region='Puducherry', verified=False)
        officer = s.scalar(m.select(m.User).where(m.User.email == 'admin@ipmprs.demo'))
        officer.rank = 'SI'
        s.add(station); s.flush()
        s.add(m.StationMembership(station_id=station.id, user_id=officer.id, assignment_role='Manager'))
        s.commit(); station_id = station.id
    from fastapi.testclient import TestClient
    with TestClient(m.app) as client:
        response = client.get('/stations', headers=auth(client, 'admin@ipmprs.demo'))
        assert response.status_code == 200
        assert any(x['code'] == 'TEST-AUTH' for x in response.json())
        assert client.get(f'/stations/{station_id}/members', headers=auth(client, 'submitter@ipmprs.demo')).status_code == 403


def test_station_capacity_and_reactivation():
    with m.SessionLocal() as s:
        station = m.Station(code='TEST-CAP', name='Capacity Test Station', region='Karaikal', verified=False)
        admin = s.scalar(m.select(m.User).where(m.User.email == 'admin@ipmprs.demo'))
        s.add(station); s.flush(); s.add(m.StationMembership(station_id=station.id, user_id=admin.id, assignment_role='Manager'))
        for i in range(49):
            user = m.User(name=f'Test Member {i}', email=f'test-member-{i}@example.test', password_hash=m.pwd.hash('Demo@123'), role='Submitter', active=True)
            s.add(user); s.flush(); s.add(m.StationMembership(station_id=station.id, user_id=user.id))
        extra = m.User(name='Extra Member', email='extra-member@example.test', password_hash=m.pwd.hash('Demo@123'), role='Submitter', active=True)
        s.add(extra); s.commit(); station_id, extra_id = station.id, extra.id
    from fastapi.testclient import TestClient
    with TestClient(m.app) as client:
        headers = auth(client, 'admin@ipmprs.demo')
        response = client.post(f'/stations/{station_id}/members', headers=headers, json={'user_id': extra_id})
        assert response.status_code == 409
        assert '50 active members' in response.json()['detail']
        with m.SessionLocal() as s:
            membership = s.scalar(m.select(m.StationMembership).where(m.StationMembership.station_id == station_id).limit(1))
            membership_id = membership.id
        assert client.delete(f'/stations/{station_id}/members/{membership_id}', headers=headers).status_code == 200
        assert client.post(f'/stations/{station_id}/members', headers=headers, json={'user_id': extra_id}).status_code == 200
