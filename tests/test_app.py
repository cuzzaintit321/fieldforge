import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

file_path = tempfile.mktemp(suffix='.db')
os.environ['DATABASE_PATH'] = file_path
os.environ['APP_SECRET'] = 'test-secret-please-do-not-use-in-production'
from app.main import app


def register(client, email, company):
    r=client.post('/api/register',json={'company':company,'name':'Test Owner','email':email,'password':'LongPassword123!'})
    assert r.status_code == 200, r.text
    return {'Authorization':'Bearer '+r.json()['token']}


def test_register_login_and_tenant_isolation():
    with TestClient(app) as c:
        a=register(c,'a@example.test','Company A')
        b=register(c,'b@example.test','Company B')
        cu=c.post('/api/customers',headers=a,json={'name':'Alice','address':'111 Main'}); assert cu.status_code==201
        aid=cu.json()['id']
        assert len(c.get('/api/customers',headers=a).json())==1
        assert c.get('/api/customers',headers=b).json()==[]
        assert c.put(f'/api/customers/{aid}',headers=b,json={'name':'Hacked'}).status_code==404
        assert c.post('/api/jobs',headers=b,json={'customer_id':aid,'title':'No access'}).status_code==404
        j=c.post('/api/jobs',headers=a,json={'customer_id':aid,'title':'Fix pool','price_cents':12500}); assert j.status_code==201,j.text
        jid=j.json()['id']
        assert c.post('/api/documents/invoices',headers=b,json={'customer_id':aid,'job_id':jid,'title':'Stolen','amount_cents':100}).status_code==404
        assert c.post('/api/documents/invoices',headers=a,json={'customer_id':aid,'job_id':jid,'title':'Pool repair','amount_cents':12500}).status_code==201
        assert c.get('/api/documents/invoices',headers=b).json()==[]
        assert c.get('/api/overview',headers=a).json()['customers']==1
        assert c.get('/api/overview',headers=b).json()['customers']==0
        login=c.post('/api/login',json={'email':'A@EXAMPLE.TEST','password':'LongPassword123!'})
        assert login.status_code==200
        assert c.get('/api/me',headers={'Authorization':'Bearer '+login.json()['token']}).json()['company']=='Company A'
        assert c.get('/api/me',headers={'Authorization':'Bearer invalid'}).status_code==401


def test_technician_restrictions():
    with TestClient(app) as c:
        owner=register(c,'owner2@example.test','Company C')
        cid=c.post('/api/customers',headers=owner,json={'name':'Client'}).json()['id']
        staff=c.post('/api/staff',headers=owner,json={'name':'Technician','email':'tech@example.test','password':'SafePassword456','role':'technician'})
        assert staff.status_code==201
        uid=staff.json()['id']
        tech_token=c.post('/api/login',json={'email':'tech@example.test','password':'SafePassword456'}).json()['token']
        tech={'Authorization':'Bearer '+tech_token}
        assigned=c.post('/api/jobs',headers=owner,json={'customer_id':cid,'title':'Assigned','assigned_to':uid}).json()['id']
        unassigned=c.post('/api/jobs',headers=owner,json={'customer_id':cid,'title':'Other'}).json()['id']
        assert len(c.get('/api/jobs',headers=tech).json())==1
        assert c.patch(f'/api/jobs/{unassigned}/status',headers=tech,json={'status':'completed'}).status_code==403
        assert c.patch(f'/api/jobs/{assigned}/status',headers=tech,json={'status':'completed'}).status_code==200
        assert c.get('/api/documents/invoices',headers=tech).status_code==403
        assert c.post('/api/customers',headers=tech,json={'name':'Cannot'}).status_code==403
        assert c.post('/api/staff',headers=tech,json={'name':'Evil','email':'evil@example.test','password':'Password12345'}).status_code==403


def test_service_catalog_and_job_notes_are_isolated():
    with TestClient(app) as c:
        a=register(c,'upgrade_a@example.test','Upgrade A')
        b=register(c,'upgrade_b@example.test','Upgrade B')
        cust=c.post('/api/customers',headers=a,json={'name':'Pool owner'}).json()['id']
        job=c.post('/api/jobs',headers=a,json={'customer_id':cust,'title':'Filter repair'}).json()['id']
        service=c.post('/api/services',headers=a,json={'name':'Pool inspection','price_cents':8900,'duration_minutes':45})
        assert service.status_code==201
        sid=service.json()['id']
        assert len(c.get('/api/services',headers=a).json())==1
        assert c.get('/api/services',headers=b).json()==[]
        assert c.put(f'/api/services/{sid}',headers=b,json={'name':'Tampered'}).status_code==404
        assert c.post(f'/api/jobs/{job}/notes',headers=a,json={'body':'Bring new cartridge'}).status_code==201
        notes=c.get(f'/api/jobs/{job}/notes',headers=a)
        assert notes.status_code==200 and len(notes.json())==1
        assert c.get(f'/api/jobs/{job}/notes',headers=b).status_code==404
        assert c.post(f'/api/jobs/{job}/notes',headers=b,json={'body':'Intruder'}).status_code==404
        assert c.get('/api/activity',headers=a).status_code==200
