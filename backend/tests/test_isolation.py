from app import main as m
from fastapi.testclient import TestClient
def auth(client,email):
    response=client.post('/auth/login',json={'email':email,'password':'Demo@123'})
    assert response.status_code==200
    return {'Authorization':'Bearer '+response.json()['token']}


def test_proposal_station_isolation_blocks_other_station_member():
    with m.SessionLocal() as s:
        stations=s.scalars(m.select(m.Station).order_by(m.Station.id)).all()
        admin=s.scalar(m.select(m.User).where(m.User.email=='admin@ipmprs.demo'))
        submitter=s.scalar(m.select(m.User).where(m.User.email=='submitter@ipmprs.demo'))
        if len(stations)<2:
            stations.append(m.Station(code='TEST-ISO',name='Isolation Test',region='Mahe',verified=False)); s.add(stations[-1]); s.flush()
        first,second=stations[0],stations[1]
        for sid in (first.id,second.id):
            if not s.scalar(m.select(m.StationMembership.id).where(m.StationMembership.station_id==sid,m.StationMembership.user_id==submitter.id,m.StationMembership.active.is_(True))):
                s.add(m.StationMembership(station_id=sid,user_id=submitter.id))
        p=m.Proposal(reference='ISO-TEST',title='Isolated proposal',summary='Station-specific access test record.',category='Technology',priority='Low',status='Draft',author_id=submitter.id,station_id=second.id)
        s.add(p); s.commit(); pid=p.id
    with TestClient(m.app) as client:
        headers=auth(client,'submitter@ipmprs.demo')
        assert client.get(f'/proposals/{pid}',headers=headers).status_code==200
        with m.SessionLocal() as s:
            s.query(m.StationMembership).filter(m.StationMembership.user_id==s.scalar(m.select(m.User).where(m.User.email=='submitter@ipmprs.demo')).id,m.StationMembership.station_id==s.scalar(m.select(m.Station).where(m.Station.id==stations[1].id)).id).update({'active':False})
            s.commit()
        assert client.get(f'/proposals/{pid}',headers=headers).status_code==403
