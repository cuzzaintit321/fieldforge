"""FieldForge: multi-tenant field service management MVP."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Literal, Optional
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

ROOT = Path(__file__).resolve().parent
DB_PATH = os.getenv("DATABASE_PATH", "/data/fieldforge.db")
SECRET = os.getenv("APP_SECRET", "")
if not SECRET:
    # Random secret by default, but sessions won't survive container restarts without APP_SECRET.
    SECRET = secrets.token_urlsafe(48)

app = FastAPI(title="FieldForge", version="0.1.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

@contextmanager
def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=20000")
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS companies(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id), email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','dispatcher','technician')), active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id), name TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id), customer_id INTEGER NOT NULL REFERENCES customers(id), title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'scheduled' CHECK(status IN ('scheduled','in_progress','completed','canceled')), scheduled_at TEXT, assigned_to INTEGER REFERENCES users(id), price_cents INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS estimates(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id), customer_id INTEGER NOT NULL REFERENCES customers(id), job_id INTEGER REFERENCES jobs(id), title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', amount_cents INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','sent','accepted','declined')), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS invoices(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id), customer_id INTEGER NOT NULL REFERENCES customers(id), job_id INTEGER REFERENCES jobs(id), title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', amount_cents INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','sent','paid','void')), due_date TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id), name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', price_cents INTEGER NOT NULL DEFAULT 0, duration_minutes INTEGER NOT NULL DEFAULT 60, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS job_notes(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id), job_id INTEGER NOT NULL REFERENCES jobs(id), author_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS idx_job_notes ON job_notes(company_id,job_id,created_at);
        CREATE INDEX IF NOT EXISTS idx_services_company ON services(company_id);
        CREATE INDEX IF NOT EXISTS idx_customers_company ON customers(company_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_company_date ON jobs(company_id,scheduled_at);
        CREATE INDEX IF NOT EXISTS idx_invoices_company ON invoices(company_id);
        ''')

@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")

def hash_password(pw: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 310_000)
    return f"{salt.hex()}:{digest.hex()}"

def check_password(pw: str, stored: str) -> bool:
    try:
        salt, hashed = stored.split(":")
        return hmac.compare_digest(hash_password(pw, bytes.fromhex(salt)), stored)
    except (ValueError, TypeError):
        return False

def token_for(user_id: int, company_id: int) -> str:
    payload = {"uid": user_id, "cid": company_id, "exp": int(time.time()) + 60 * 60 * 24 * 7}
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"

def auth(request: Request):
    value = request.headers.get("authorization", "")
    if not value.startswith("Bearer "):
        raise HTTPException(401, "Please sign in")
    try:
        raw, sig = value[7:].split(".")
        valid = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(valid, sig):
            raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if payload["exp"] < time.time():
            raise ValueError()
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise HTTPException(401, "Session expired")
    with db() as c:
        row = c.execute("SELECT id,company_id,name,email,role FROM users WHERE id=? AND company_id=? AND active=1", (payload["uid"], payload["cid"])).fetchone()
    if not row:
        raise HTTPException(401, "Account not found")
    return dict(row)

def manager(user=Depends(auth)):
    if user["role"] == "technician":
        raise HTTPException(403, "Dispatcher or owner access required")
    return user

def owner(user=Depends(auth)):
    if user["role"] != "owner":
        raise HTTPException(403, "Owner access required")
    return user

def one(c, query, args=()):
    r = c.execute(query, args).fetchone()
    if r is None:
        raise HTTPException(404, "Record not found")
    return dict(r)

def owned(c, table: str, record_id: int, cid: int):
    # table is only ever a developer-defined literal, never user-supplied
    return one(c, f"SELECT * FROM {table} WHERE id=? AND company_id=?", (record_id, cid))

def validate_link(c, table: str, record_id: Optional[int], cid: int):
    if record_id is not None:
        owned(c, table, record_id, cid)

def clean_email(e: str):
    return e.strip().lower()

class Register(BaseModel):
    company: str = Field(min_length=2, max_length=100)
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=10, max_length=200)

class Login(BaseModel):
    email: str
    password: str

@app.post("/api/register")
def register(data: Register):
    if "@" not in data.email:
        raise HTTPException(422, "Invalid email")
    with db() as c:
        try:
            c.execute("BEGIN IMMEDIATE")
            cid = c.execute("INSERT INTO companies(name) VALUES (?)", (data.company.strip(),)).lastrowid
            uid = c.execute("INSERT INTO users(company_id,email,name,password_hash,role) VALUES (?,?,?,?,?)", (cid,clean_email(data.email),data.name.strip(),hash_password(data.password),"owner")).lastrowid
            c.execute("COMMIT")
        except sqlite3.IntegrityError:
            c.execute("ROLLBACK")
            raise HTTPException(409, "Email already registered")
    return {"token": token_for(uid,cid)}

@app.post("/api/login")
def login(data: Login):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE email=? AND active=1", (clean_email(data.email),)).fetchone()
    if not row or not check_password(data.password, row["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    return {"token": token_for(row["id"],row["company_id"])}

@app.get("/api/me")
def me(u=Depends(auth)):
    with db() as c:
        company = one(c,"SELECT name FROM companies WHERE id=?",(u["company_id"],))
    return {**u, "company": company["name"]}

class StaffIn(BaseModel):
    name: str = Field(min_length=2,max_length=100)
    email: str = Field(min_length=5,max_length=200)
    password: str = Field(min_length=10,max_length=200)
    role: Literal["dispatcher", "technician"] = "technician"

@app.get("/api/staff")
def staff(u=Depends(auth)):
    with db() as c:
        rows = c.execute("SELECT id,name,email,role FROM users WHERE company_id=? AND active=1 ORDER BY name",(u["company_id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/staff",status_code=201)
def create_staff(data: StaffIn,u=Depends(owner)):
    with db() as c:
        try:
            cur=c.execute("INSERT INTO users(company_id,name,email,password_hash,role) VALUES (?,?,?,?,?)",(u["company_id"],data.name.strip(),clean_email(data.email),hash_password(data.password),data.role))
        except sqlite3.IntegrityError:
            raise HTTPException(409,"Email already registered")
        return {"id":cur.lastrowid}

class CustomerIn(BaseModel):
    name: str = Field(min_length=1,max_length=150)
    email: str = Field(default="",max_length=200)
    phone: str = Field(default="",max_length=50)
    address: str = Field(default="",max_length=350)
    notes: str = Field(default="",max_length=2000)

@app.get("/api/customers")
def customers(q: str="",u=Depends(auth)):
    with db() as c:
        rows=c.execute("SELECT * FROM customers WHERE company_id=? AND (name LIKE ? OR phone LIKE ? OR address LIKE ?) ORDER BY name LIMIT 500",(u["company_id"],f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
    return [dict(x) for x in rows]

@app.post("/api/customers",status_code=201)
def create_customer(data: CustomerIn,u=Depends(manager)):
    with db() as c:
        cid=c.execute("INSERT INTO customers(company_id,name,email,phone,address,notes) VALUES (?,?,?,?,?,?)",(u["company_id"],data.name.strip(),data.email,data.phone,data.address,data.notes)).lastrowid
    return {"id":cid}

@app.put("/api/customers/{rid}")
def update_customer(rid:int,data:CustomerIn,u=Depends(manager)):
    with db() as c:
        owned(c,"customers",rid,u["company_id"])
        c.execute("UPDATE customers SET name=?,email=?,phone=?,address=?,notes=? WHERE id=? AND company_id=?",(data.name.strip(),data.email,data.phone,data.address,data.notes,rid,u["company_id"]))
    return {"ok":True}

class JobIn(BaseModel):
    customer_id:int
    title:str=Field(min_length=1,max_length=200)
    description:str=Field(default="",max_length=5000)
    scheduled_at:Optional[str]=None
    assigned_to:Optional[int]=None
    price_cents:int=Field(default=0,ge=0,le=100_000_000)
    status:Literal["scheduled","in_progress","completed","canceled"]="scheduled"
    @field_validator("scheduled_at")
    @classmethod
    def check_date(cls,v):
        if v:
            try: datetime.fromisoformat(v.replace("Z","+00:00"))
            except ValueError: raise ValueError("Invalid schedule date")
        return v or None

@app.get("/api/jobs")
def jobs(u=Depends(auth)):
    with db() as c:
        sql="""SELECT j.*,c.name AS customer_name,c.address AS customer_address,s.name AS staff_name FROM jobs j JOIN customers c ON c.id=j.customer_id AND c.company_id=j.company_id LEFT JOIN users s ON s.id=j.assigned_to AND s.company_id=j.company_id WHERE j.company_id=?"""
        args=[u["company_id"]]
        if u["role"]=="technician":
            sql+=" AND j.assigned_to=?"
            args.append(u["id"])
        rows=c.execute(sql+" ORDER BY COALESCE(j.scheduled_at,'9999') ASC,j.id DESC LIMIT 1000",args).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/jobs",status_code=201)
def create_job(data:JobIn,u=Depends(manager)):
    with db() as c:
        validate_link(c,"customers",data.customer_id,u["company_id"])
        if data.assigned_to is not None: validate_link(c,"users",data.assigned_to,u["company_id"])
        rid=c.execute("INSERT INTO jobs(company_id,customer_id,title,description,scheduled_at,assigned_to,price_cents,status) VALUES (?,?,?,?,?,?,?,?)",(u["company_id"],data.customer_id,data.title,data.description,data.scheduled_at,data.assigned_to,data.price_cents,data.status)).lastrowid
    return {"id":rid}

@app.put("/api/jobs/{rid}")
def update_job(rid:int,data:JobIn,u=Depends(manager)):
    with db() as c:
        owned(c,"jobs",rid,u["company_id"])
        validate_link(c,"customers",data.customer_id,u["company_id"])
        if data.assigned_to is not None: validate_link(c,"users",data.assigned_to,u["company_id"])
        c.execute("UPDATE jobs SET customer_id=?,title=?,description=?,scheduled_at=?,assigned_to=?,price_cents=?,status=? WHERE id=? AND company_id=?",(data.customer_id,data.title,data.description,data.scheduled_at,data.assigned_to,data.price_cents,data.status,rid,u["company_id"]))
    return {"ok":True}

class JobStatus(BaseModel):
    status:Literal["scheduled","in_progress","completed","canceled"]

@app.patch("/api/jobs/{rid}/status")
def job_status(rid:int,data:JobStatus,u=Depends(auth)):
    with db() as c:
        record=owned(c,"jobs",rid,u["company_id"])
        if u["role"]=="technician" and record["assigned_to"]!=u["id"]:
            raise HTTPException(403,"Not assigned to this job")
        c.execute("UPDATE jobs SET status=? WHERE id=? AND company_id=?",(data.status,rid,u["company_id"]))
    return {"ok":True}

class DocumentIn(BaseModel):
    customer_id:int
    job_id:Optional[int]=None
    title:str=Field(min_length=1,max_length=200)
    description:str=Field(default="",max_length=4000)
    amount_cents:int=Field(ge=0,le=100_000_000)
    due_date:Optional[str]=None

@app.get("/api/documents/{kind}")
def documents(kind:Literal["estimates","invoices"],u=Depends(auth)):
    if u["role"]=="technician": raise HTTPException(403,"Access restricted")
    with db() as c:
        rows=c.execute(f"SELECT d.*, c.name AS customer_name FROM {kind} d JOIN customers c ON c.id=d.customer_id AND c.company_id=d.company_id WHERE d.company_id=? ORDER BY d.id DESC LIMIT 500",(u["company_id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/documents/{kind}",status_code=201)
def create_document(kind:Literal["estimates","invoices"],data:DocumentIn,u=Depends(manager)):
    if data.due_date:
        try: date.fromisoformat(data.due_date)
        except ValueError: raise HTTPException(422,"Invalid due date")
    with db() as c:
        validate_link(c,"customers",data.customer_id,u["company_id"])
        if data.job_id is not None:
            job=owned(c,"jobs",data.job_id,u["company_id"])
            if job["customer_id"]!=data.customer_id: raise HTTPException(422,"Job belongs to another customer")
        if kind=="invoices":
            rid=c.execute("INSERT INTO invoices(company_id,customer_id,job_id,title,description,amount_cents,due_date) VALUES (?,?,?,?,?,?,?)",(u["company_id"],data.customer_id,data.job_id,data.title,data.description,data.amount_cents,data.due_date)).lastrowid
        else:
            rid=c.execute("INSERT INTO estimates(company_id,customer_id,job_id,title,description,amount_cents) VALUES (?,?,?,?,?,?)",(u["company_id"],data.customer_id,data.job_id,data.title,data.description,data.amount_cents)).lastrowid
    return {"id":rid}

class DocStatus(BaseModel):
    status:str

@app.patch("/api/documents/{kind}/{rid}/status")
def document_status(kind:Literal["estimates","invoices"],rid:int,data:DocStatus,u=Depends(manager)):
    allowed={"invoices":{"draft","sent","paid","void"},"estimates":{"draft","sent","accepted","declined"}}
    if data.status not in allowed[kind]: raise HTTPException(422,"Invalid status")
    with db() as c:
        owned(c,kind,rid,u["company_id"])
        c.execute(f"UPDATE {kind} SET status=? WHERE id=? AND company_id=?",(data.status,rid,u["company_id"]))
    return {"ok":True}

@app.get("/api/overview")
def overview(u=Depends(auth)):
    cid=u["company_id"]
    with db() as c:
        if u["role"]=="technician":
            jobs_count=c.execute("SELECT count(*) FROM jobs WHERE company_id=? AND assigned_to=? AND status NOT IN ('completed','canceled')",(cid,u["id"])).fetchone()[0]
            done=c.execute("SELECT count(*) FROM jobs WHERE company_id=? AND assigned_to=? AND status='completed'",(cid,u["id"])).fetchone()[0]
            return {"active_jobs":jobs_count,"completed_jobs":done}
        return {
            "customers":c.execute("SELECT count(*) FROM customers WHERE company_id=?",(cid,)).fetchone()[0],
            "active_jobs":c.execute("SELECT count(*) FROM jobs WHERE company_id=? AND status NOT IN ('completed','canceled')",(cid,)).fetchone()[0],
            "unpaid_cents":c.execute("SELECT COALESCE(sum(amount_cents),0) FROM invoices WHERE company_id=? AND status='sent'",(cid,)).fetchone()[0],
            "paid_cents":c.execute("SELECT COALESCE(sum(amount_cents),0) FROM invoices WHERE company_id=? AND status='paid'",(cid,)).fetchone()[0]
        }

@app.get("/api/health")
def health():
    return {"status":"ok"}


# Additional operational tools, added without changing existing table layouts.
class ServiceIn(BaseModel):
    name: str = Field(min_length=1,max_length=150)
    description: str = Field(default="",max_length=2000)
    price_cents: int = Field(default=0,ge=0,le=100_000_000)
    duration_minutes: int = Field(default=60,ge=5,le=1440)
    active: bool = True

@app.get("/api/services")
def list_services(u=Depends(auth)):
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM services WHERE company_id=? ORDER BY active DESC,name",(u["company_id"],)).fetchall()]

@app.post("/api/services",status_code=201)
def create_service(data:ServiceIn,u=Depends(manager)):
    with db() as c:
        rid=c.execute("INSERT INTO services(company_id,name,description,price_cents,duration_minutes,active) VALUES (?,?,?,?,?,?)",(u["company_id"],data.name.strip(),data.description,data.price_cents,data.duration_minutes,int(data.active))).lastrowid
    return {"id":rid}

@app.put("/api/services/{rid}")
def edit_service(rid:int,data:ServiceIn,u=Depends(manager)):
    with db() as c:
        owned(c,"services",rid,u["company_id"])
        c.execute("UPDATE services SET name=?,description=?,price_cents=?,duration_minutes=?,active=? WHERE company_id=? AND id=?",(data.name.strip(),data.description,data.price_cents,data.duration_minutes,int(data.active),u["company_id"],rid))
    return {"ok":True}

class NoteIn(BaseModel):
    body: str = Field(min_length=1,max_length=3000)


def accessible_job(c,job_id,u):
    job=owned(c,"jobs",job_id,u["company_id"])
    if u["role"]=="technician" and job["assigned_to"]!=u["id"]:
        raise HTTPException(403,"Not assigned to this job")
    return job

@app.get("/api/jobs/{rid}/notes")
def get_notes(rid:int,u=Depends(auth)):
    with db() as c:
        accessible_job(c,rid,u)
        return [dict(r) for r in c.execute("SELECT n.id,n.body,n.created_at,a.name AS author FROM job_notes n JOIN users a ON a.id=n.author_id AND a.company_id=n.company_id WHERE n.job_id=? AND n.company_id=? ORDER BY n.id DESC LIMIT 200",(rid,u["company_id"])).fetchall()]

@app.post("/api/jobs/{rid}/notes",status_code=201)
def add_note(rid:int,data:NoteIn,u=Depends(auth)):
    with db() as c:
        accessible_job(c,rid,u)
        nid=c.execute("INSERT INTO job_notes(company_id,job_id,author_id,body) VALUES (?,?,?,?)",(u["company_id"],rid,u["id"],data.body.strip())).lastrowid
    return {"id":nid}

@app.get("/api/activity")
def activity(u=Depends(auth)):
    if u["role"]=="technician":
        raise HTTPException(403,"Access restricted")
    with db() as c:
        rows=c.execute("""SELECT 'job' AS kind,id,title AS label,created_at FROM jobs WHERE company_id=? UNION ALL
          SELECT 'customer',id,name,created_at FROM customers WHERE company_id=? UNION ALL
          SELECT 'invoice',id,title,created_at FROM invoices WHERE company_id=? UNION ALL
          SELECT 'estimate',id,title,created_at FROM estimates WHERE company_id=?
          ORDER BY created_at DESC,id DESC LIMIT 12""",(u["company_id"],)*4).fetchall()
        return [dict(x) for x in rows]
