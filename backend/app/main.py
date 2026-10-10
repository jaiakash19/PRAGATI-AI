"""IPMPRS API: authenticated proposal workflow and precedent retrieval."""
import csv, hashlib, io, os, re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, JSON, create_engine, select, func, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

APP_ENV = os.getenv("APP_ENV", "development").lower()
DATABASE_URL = os.getenv("DATABASE_URL") or ("sqlite:///./ipmprs.db" if APP_ENV != "production" else "")
SECRET_KEY = os.getenv("SECRET_KEY", "development-secret-change-me")
if not DATABASE_URL: raise RuntimeError("DATABASE_URL is required in production")
if APP_ENV == "production" and (SECRET_KEY == "development-secret-change-me" or len(SECRET_KEY) < 32): raise RuntimeError("Set a strong SECRET_KEY in production")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "uploads")); UPLOAD_DIR.mkdir(exist_ok=True)
engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
# PBKDF2 avoids platform-specific bcrypt binary issues while retaining salted password hashes.
pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security = HTTPBearer()
ROLES = {"Admin", "Submitter", "Reviewer", "Approving Officer", "Implementation Officer"}
_embedding_model = None
try:
    from pgvector.sqlalchemy import Vector
    VECTOR_COLUMN = Vector(384).with_variant(JSON(), "sqlite")
except ImportError:
    VECTOR_COLUMN = JSON()

class Base(DeclarativeBase): pass
class Department(Base):
    __tablename__="departments"; id: Mapped[int]=mapped_column(primary_key=True); name: Mapped[str]=mapped_column(String(120), unique=True)
class User(Base):
    __tablename__="users"; id: Mapped[int]=mapped_column(primary_key=True); name: Mapped[str]=mapped_column(String(120)); email: Mapped[str]=mapped_column(String(180), unique=True); password_hash: Mapped[str]=mapped_column(String(255)); role: Mapped[str]=mapped_column(String(40)); department_id: Mapped[Optional[int]]=mapped_column(ForeignKey("departments.id"), nullable=True); active: Mapped[bool]=mapped_column(default=True)
class Proposal(Base):
    __tablename__="proposals"; id: Mapped[int]=mapped_column(primary_key=True); reference: Mapped[str]=mapped_column(String(40), unique=True); title: Mapped[str]=mapped_column(String(240)); summary: Mapped[str]=mapped_column(Text); category: Mapped[str]=mapped_column(String(80)); priority: Mapped[str]=mapped_column(String(20), default="Medium"); status: Mapped[str]=mapped_column(String(30), default="Draft"); author_id: Mapped[int]=mapped_column(ForeignKey("users.id")); department_id: Mapped[Optional[int]]=mapped_column(ForeignKey("departments.id")); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda:datetime.now(timezone.utc)); updated_at: Mapped[datetime]=mapped_column(DateTime, default=lambda:datetime.now(timezone.utc)); decision: Mapped[Optional[str]]=mapped_column(Text, nullable=True); observations: Mapped[Optional[str]]=mapped_column(Text, nullable=True); outcome: Mapped[Optional[str]]=mapped_column(Text, nullable=True)
    documents: Mapped[list["Document"]]=relationship(back_populates="proposal", cascade="all, delete-orphan")
class Document(Base):
    __tablename__="documents"; id: Mapped[int]=mapped_column(primary_key=True); proposal_id: Mapped[int]=mapped_column(ForeignKey("proposals.id")); filename: Mapped[str]=mapped_column(String(255)); stored_name: Mapped[str]=mapped_column(String(255)); content_type: Mapped[str]=mapped_column(String(100)); extracted_text: Mapped[str]=mapped_column(Text, default=""); version: Mapped[int]=mapped_column(Integer, default=1); uploaded_at: Mapped[datetime]=mapped_column(DateTime, default=lambda:datetime.now(timezone.utc)); proposal: Mapped[Proposal]=relationship(back_populates="documents")
class ProposalEmbedding(Base):
    __tablename__="proposal_embeddings"; id: Mapped[int]=mapped_column(primary_key=True); proposal_id: Mapped[int]=mapped_column(ForeignKey("proposals.id"), unique=True); model: Mapped[str]=mapped_column(String(120)); vector: Mapped[list]=mapped_column(VECTOR_COLUMN); source_hash: Mapped[str]=mapped_column(String(64)); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda:datetime.now(timezone.utc))
class Assignment(Base):
    __tablename__="assignments"; id: Mapped[int]=mapped_column(primary_key=True); proposal_id: Mapped[int]=mapped_column(ForeignKey("proposals.id")); user_id: Mapped[int]=mapped_column(ForeignKey("users.id")); role: Mapped[str]=mapped_column(String(50))
class Review(Base):
    __tablename__="reviews"; id: Mapped[int]=mapped_column(primary_key=True); proposal_id: Mapped[int]=mapped_column(ForeignKey("proposals.id")); reviewer_id: Mapped[int]=mapped_column(ForeignKey("users.id")); action: Mapped[str]=mapped_column(String(50)); reason: Mapped[str]=mapped_column(Text); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda:datetime.now(timezone.utc))
class Implementation(Base):
    __tablename__="implementations"; id: Mapped[int]=mapped_column(primary_key=True); proposal_id: Mapped[int]=mapped_column(ForeignKey("proposals.id"), unique=True); progress: Mapped[int]=mapped_column(Integer, default=0); milestone: Mapped[str]=mapped_column(String(240), default="Initiated"); evidence: Mapped[str]=mapped_column(Text, default=""); closed_at: Mapped[Optional[datetime]]=mapped_column(DateTime, nullable=True)
class Notification(Base):
    __tablename__="notifications"; id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[int]=mapped_column(ForeignKey("users.id")); message: Mapped[str]=mapped_column(Text); read: Mapped[bool]=mapped_column(default=False); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda:datetime.now(timezone.utc))
class AuditLog(Base):
    __tablename__="audit_logs"; id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[Optional[int]]=mapped_column(ForeignKey("users.id"), nullable=True); action: Mapped[str]=mapped_column(String(120)); entity: Mapped[str]=mapped_column(String(50)); entity_id: Mapped[int]=mapped_column(Integer); details: Mapped[str]=mapped_column(Text, default=""); created_at: Mapped[datetime]=mapped_column(DateTime, default=lambda:datetime.now(timezone.utc))

class Login(BaseModel): email:str; password:str
class ProposalIn(BaseModel): title:str=Field(min_length=3,max_length=240); summary:str=Field(min_length=10); category:str; priority:str="Medium"; department_id:Optional[int]=None
class ActionIn(BaseModel): action:str; reason:str=Field(min_length=3)
class ImplementationIn(BaseModel): progress:int=Field(ge=0,le=100); milestone:str; evidence:str=""
class UserIn(BaseModel): name:str=Field(min_length=2,max_length=120); email:str; role:str; password:Optional[str]=Field(default=None,min_length=8); department_id:Optional[int]=None; active:bool=True
class ProposalUpdate(BaseModel): title:str=Field(min_length=3,max_length=240); summary:str=Field(min_length=10); category:str; priority:str; department_id:Optional[int]=None
class AssignmentIn(BaseModel): user_id:int; role:str=Field(min_length=2,max_length=50)

def db():
    with SessionLocal() as s: yield s
def audit(s, u, action, entity, entity_id, details=""):
    s.add(AuditLog(user_id=u.id if u else None, action=action, entity=entity, entity_id=entity_id, details=details))
def notify(s, user_id, message): s.add(Notification(user_id=user_id,message=message))
def token_for(u): return jwt.encode({"sub":str(u.id),"role":u.role,"exp":datetime.now(timezone.utc)+timedelta(hours=8)}, SECRET_KEY, algorithm="HS256")
def current(c:HTTPAuthorizationCredentials=Depends(security), s:Session=Depends(db)):
    try: uid=int(jwt.decode(c.credentials, SECRET_KEY, algorithms=["HS256"])["sub"])
    except (JWTError, ValueError): raise HTTPException(401,"Invalid session")
    u=s.get(User,uid)
    if not u or not u.active: raise HTTPException(401,"Inactive account")
    return u
def allow(*roles):
    def check(u=Depends(current)):
        if u.role not in roles: raise HTTPException(403,"Insufficient permission")
        return u
    return check
def can_access_proposal(s, u, p):
    """Submitters are confined to their own or explicitly assigned records."""
    if u.role != "Submitter" or u.role == "Admin": return True
    return p.author_id == u.id or bool(s.scalar(select(Assignment.id).where(Assignment.proposal_id==p.id, Assignment.user_id==u.id)))
def assignment_allows(s, u, p):
    assignments=list(s.scalars(select(Assignment).where(Assignment.proposal_id==p.id)).all())
    return not assignments or any(a.user_id==u.id for a in assignments)
def proposal_dict(p): return {"id":p.id,"reference":p.reference,"title":p.title,"summary":p.summary,"category":p.category,"priority":p.priority,"status":p.status,"created_at":p.created_at,"decision":p.decision,"observations":p.observations,"outcome":p.outcome}
def user_dict(x): return {"id":x.id,"name":x.name,"email":x.email,"role":x.role,"department_id":x.department_id,"active":x.active}
def words(t): return set(re.findall(r"[a-z]{3,}",t.lower()))
def score(query, p):
    a,b=words(query),words(p.title+" "+p.summary+" "+(p.observations or "")+" "+(p.outcome or "")); return round(100*len(a&b)/max(1,len(a|b)),1)
def embedding(text):
    """Lazy local model: no API key; returns None so lexical fallback remains available offline."""
    global _embedding_model
    try:
        if _embedding_model is None:
            from sentence_transformers import SentenceTransformer
            _embedding_model=SentenceTransformer("all-MiniLM-L6-v2")
        return _embedding_model.encode(text, normalize_embeddings=True).tolist()
    except Exception: return None
def cosine(a,b): return round(100*sum(x*y for x,y in zip(a,b)),1)
def store_embedding(s, p):
    source=p.title+" "+p.summary+" "+" ".join(d.extracted_text for d in p.documents)
    vector=embedding(source)
    if not vector: return False
    digest=hashlib.sha256(source.encode()).hexdigest(); record=s.scalar(select(ProposalEmbedding).where(ProposalEmbedding.proposal_id==p.id))
    if record: record.vector,record.source_hash,record.created_at=vector,digest,datetime.now(timezone.utc)
    else: s.add(ProposalEmbedding(proposal_id=p.id,model="all-MiniLM-L6-v2",vector=vector,source_hash=digest))
    return True
def extract_text(raw, content_type):
    try:
        if content_type=="text/plain": return raw.decode("utf-8", errors="replace")
        if content_type=="application/pdf":
            from pypdf import PdfReader
            import io
            return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(raw)).pages)
        if "wordprocessingml" in content_type:
            from docx import Document as WordDocument
            import io
            return "\n".join(x.text for x in WordDocument(io.BytesIO(raw)).paragraphs)
    except Exception: return ""
    return ""

@asynccontextmanager
async def lifespan(_: FastAPI):
    """Development/test schema bootstrap; production is migrated by Alembic."""
    if APP_ENV != "production": Base.metadata.create_all(engine)
    with SessionLocal() as s:
        if (APP_ENV != "production" or os.getenv("DEMO_SEED", "false").lower() == "true") and not s.scalar(select(User.id).limit(1)): seed(s)
    yield

allowed_origins=os.getenv("CORS_ORIGINS","http://localhost:5173").split(",")
if APP_ENV == "production" and "*" in allowed_origins: raise RuntimeError("Wildcard CORS is forbidden in production")
app=FastAPI(title="IPMPRS", lifespan=lifespan, docs_url="/docs" if APP_ENV != "production" else None, redoc_url=None)
app.add_middleware(CORSMiddleware,allow_origins=allowed_origins,allow_credentials=True,allow_methods=["GET","POST","PUT"],allow_headers=["Authorization","Content-Type"])
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff";response.headers["X-Frame-Options"]="DENY";response.headers["Referrer-Policy"]="no-referrer"
    return response
@app.get("/health")
def health(s:Session=Depends(db)):
    s.execute(text("SELECT 1")); return {"status":"ok","environment":APP_ENV,"database":"postgresql" if DATABASE_URL.startswith("postgresql") else "sqlite"}
def seed(s):
    d=Department(name="Police Modernisation Directorate"); s.add(d); s.flush()
    users=[("System Administrator","admin@ipmprs.demo","Admin"),("Asha Verma","submitter@ipmprs.demo","Submitter"),("Rahul Singh","reviewer@ipmprs.demo","Reviewer"),("Maya Nair","approver@ipmprs.demo","Approving Officer"),("Vikram Rao","implementation@ipmprs.demo","Implementation Officer")]
    for n,e,r in users:s.add(User(name=n,email=e,password_hash=pwd.hash("Demo@123"),role=r,department_id=d.id))
    s.flush(); author=s.scalar(select(User).where(User.email=="submitter@ipmprs.demo"))
    samples=[("IPM-2025-001","Body-worn camera pilot","Pilot cameras for traffic patrol teams.","Technology","Closed","Approved","Privacy assessment completed; phased deployment recommended.","Pilot completed with 92% evidence integrity compliance."),("IPM-2025-002","Women safety response desk","Establish dedicated response desks at district stations.","Community Safety","Implemented","Approved","Interdepartmental training required.","All 12 desks operational; response times improved.")]
    for ref,title,summary,cat,status,decision,obs,out in samples:s.add(Proposal(reference=ref,title=title,summary=summary,category=cat,priority="High",status=status,author_id=author.id,department_id=d.id,decision=decision,observations=obs,outcome=out))
    s.commit()

@app.post("/auth/login")
def login(body:Login,s:Session=Depends(db)):
    u=s.scalar(select(User).where(User.email==body.email))
    if not u or not pwd.verify(body.password,u.password_hash): raise HTTPException(401,"Invalid email or password")
    return {"token":token_for(u),"user":{"name":u.name,"role":u.role,"email":u.email}}
@app.get("/auth/me")
def me(u=Depends(current)): return {"id":u.id,"name":u.name,"email":u.email,"role":u.role}
@app.get("/dashboard")
def dashboard(u=Depends(current),s:Session=Depends(db)):
    total=s.scalar(select(func.count(Proposal.id))) or 0; rows=s.scalars(select(Proposal).order_by(Proposal.updated_at.desc()).limit(6)).all()
    return {"stats":{"total":total,"pending":s.scalar(select(func.count(Proposal.id)).where(Proposal.status.in_(["Submitted","Under Review","Recommended"]))) or 0,"approved":s.scalar(select(func.count(Proposal.id)).where(Proposal.status.in_(["Approved","Implemented","Closed"]))) or 0,"implemented":s.scalar(select(func.count(Proposal.id)).where(Proposal.status.in_(["Implemented","Closed"]))) or 0},"recent":[proposal_dict(x) for x in rows]}
@app.get("/proposals")
def proposals(q:str="",status:str="",u=Depends(current),s:Session=Depends(db)):
    st=select(Proposal).order_by(Proposal.updated_at.desc())
    if u.role == "Submitter": st=st.where((Proposal.author_id==u.id) | Proposal.id.in_(select(Assignment.proposal_id).where(Assignment.user_id==u.id)))
    if q: st=st.where(Proposal.title.ilike(f"%{q}%") | Proposal.reference.ilike(f"%{q}%"))
    if status: st=st.where(Proposal.status==status)
    return [proposal_dict(x) for x in s.scalars(st).all()]
@app.post("/proposals")
def create(body:ProposalIn,u=Depends(allow("Admin","Submitter")),s:Session=Depends(db)):
    p=Proposal(reference=f"IPM-{datetime.now().year}-{(s.scalar(select(func.count(Proposal.id))) or 0)+1:03d}",author_id=u.id,**body.model_dump());s.add(p);s.flush();store_embedding(s,p)
    audit(s,u,"Created","proposal",p.id);s.commit();return proposal_dict(p)
@app.put("/proposals/{pid}")
def update_proposal(pid:int,body:ProposalUpdate,u=Depends(current),s:Session=Depends(db)):
    p=s.get(Proposal,pid)
    if not p: raise HTTPException(404,"Proposal not found")
    if u.role!="Admin" and p.author_id!=u.id: raise HTTPException(403,"Only the author may edit this proposal")
    if p.status not in {"Draft","Modifications Requested"}: raise HTTPException(409,"Only draft or returned proposals can be edited")
    for k,v in body.model_dump().items(): setattr(p,k,v)
    p.updated_at=datetime.now(timezone.utc); audit(s,u,"Updated","proposal",pid);s.commit();return proposal_dict(p)
@app.get("/proposals/{pid}")
def get_proposal(pid:int,u=Depends(current),s:Session=Depends(db)):
    p=s.get(Proposal,pid)
    if not p:raise HTTPException(404,"Proposal not found")
    if not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this proposal")
    r=proposal_dict(p);r["documents"]=[{"id":d.id,"filename":d.filename,"version":d.version,"uploaded_at":d.uploaded_at,"content_type":d.content_type} for d in p.documents];r["reviews"]=[{"action":x.action,"reason":x.reason,"created_at":x.created_at} for x in s.scalars(select(Review).where(Review.proposal_id==pid)).all()]; impl=s.scalar(select(Implementation).where(Implementation.proposal_id==pid));r["implementation"]={"progress":impl.progress,"milestone":impl.milestone,"evidence":impl.evidence,"closed_at":impl.closed_at} if impl else None;r["assignments"]=[{"id":a.id,"user_id":a.user_id,"role":a.role} for a in s.scalars(select(Assignment).where(Assignment.proposal_id==pid)).all()];return r
@app.post("/proposals/{pid}/action")
def action(pid:int,body:ActionIn,u=Depends(current),s:Session=Depends(db)):
    p=s.get(Proposal,pid)
    if not p:raise HTTPException(404,"Proposal not found")
    if not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this proposal")
    transition={"submit":("Submitted",{"Submitter","Admin"},{"Draft","Modifications Requested"}),"review":("Under Review",{"Reviewer","Admin"},{"Submitted"}),"modifications":("Modifications Requested",{"Reviewer","Admin"},{"Submitted","Under Review"}),"recommend":("Recommended",{"Reviewer","Admin"},{"Under Review"}),"approve":("Approved",{"Approving Officer","Admin"},{"Recommended"}),"reject":("Rejected",{"Approving Officer","Admin"},{"Recommended"})}
    if body.action not in transition:raise HTTPException(422,"Unknown action")
    new,roles,states=transition[body.action]
    if u.role not in roles:raise HTTPException(403,"Role cannot perform this action")
    if p.status not in states: raise HTTPException(409,f"Cannot {body.action} a proposal in {p.status}")
    if u.role != "Admin" and not assignment_allows(s,u,p): raise HTTPException(403,"Proposal is assigned to another officer")
    p.status=new;p.decision=body.action.title() if body.action in {"approve","reject"} else p.decision;p.observations=body.reason;p.updated_at=datetime.now(timezone.utc);s.add(Review(proposal_id=pid,reviewer_id=u.id,action=body.action,reason=body.reason)); notify(s,p.author_id,f"{p.reference}: {new}. {body.reason}");audit(s,u,body.action,"proposal",pid,body.reason);s.commit();return proposal_dict(p)
@app.get("/proposals/{pid}/precedents")
def precedents(pid:int,u=Depends(current),s:Session=Depends(db)):
    p=s.get(Proposal,pid)
    if not p:raise HTTPException(404,"Proposal not found")
    if not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this proposal")
    candidates=[x for x in s.scalars(select(Proposal).where(Proposal.id!=pid,Proposal.status.in_(["Approved","Implemented","Closed"]))).all()]; query=p.title+" "+p.summary; qv=embedding(query)
    # pgvector does the ranking in PostgreSQL when model weights are available. Any model/database
    # failure deliberately falls back to deterministic lexical retrieval rather than inventing a score.
    if qv and DATABASE_URL.startswith("postgresql"):
        try:
            rows=s.execute(select(Proposal,ProposalEmbedding.vector.cosine_distance(qv).label("distance")).join(ProposalEmbedding,ProposalEmbedding.proposal_id==Proposal.id).where(Proposal.id!=pid,Proposal.status.in_(["Approved","Implemented","Closed"])).order_by("distance").limit(5)).all()
            return [{**proposal_dict(x),"similarity":round(max(0,100*(1-float(distance))),1),"matched_excerpt":x.summary[:220],"method":"semantic pgvector"} for x,distance in rows]
        except Exception: s.rollback()
    return [{**proposal_dict(x),"similarity":score(query,x),"matched_excerpt":x.summary[:220],"method":"lexical fallback"} for x in sorted(candidates,key=lambda x:score(query,x),reverse=True)[:5]]
@app.post("/proposals/{pid}/implementation")
def implementation(pid:int,body:ImplementationIn,u=Depends(allow("Implementation Officer","Admin")),s:Session=Depends(db)):
    p=s.get(Proposal,pid)
    if not p:raise HTTPException(404,"Proposal not found")
    if p.status not in {"Approved","Implemented"}: raise HTTPException(409,"Implementation requires an approved proposal")
    if u.role != "Admin" and not assignment_allows(s,u,p): raise HTTPException(403,"Proposal is assigned to another officer")
    rec=s.scalar(select(Implementation).where(Implementation.proposal_id==pid)) or Implementation(proposal_id=pid);rec.progress=body.progress;rec.milestone=body.milestone;rec.evidence=body.evidence
    if body.progress==100:rec.closed_at=datetime.now(timezone.utc);p.status="Closed";p.outcome=body.evidence
    else:p.status="Implemented"
    s.add(rec);audit(s,u,"Updated implementation","proposal",pid);s.commit();return {"progress":rec.progress,"status":p.status}
@app.post("/proposals/{pid}/documents")
def upload(pid:int,file:UploadFile=File(...),u=Depends(allow("Admin","Submitter")),s:Session=Depends(db)):
    if file.content_type not in {"application/pdf","application/vnd.openxmlformats-officedocument.wordprocessingml.document","text/plain"}:raise HTTPException(415,"Only PDF, DOCX and TXT permitted")
    p=s.get(Proposal,pid)
    if not p:raise HTTPException(404,"Proposal not found")
    if not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this proposal")
    raw=file.file.read()
    if len(raw)>10_000_000:raise HTTPException(413,"File too large")
    name=hashlib.sha256(raw).hexdigest()+Path(file.filename).suffix; (UPLOAD_DIR/name).write_bytes(raw);d=Document(proposal_id=pid,filename=Path(file.filename).name,stored_name=name,content_type=file.content_type,extracted_text=extract_text(raw,file.content_type)) ;s.add(d);s.flush();store_embedding(s,p);audit(s,u,"Uploaded document","document",d.id);s.commit();return {"id":d.id,"filename":d.filename}
@app.get("/documents")
def documents(q:str="",u=Depends(current),s:Session=Depends(db)):
    st=select(Document,Proposal).join(Proposal,Document.proposal_id==Proposal.id).order_by(Document.uploaded_at.desc())
    if q: st=st.where(Document.filename.ilike(f"%{q}%") | Proposal.reference.ilike(f"%{q}%") | Document.extracted_text.ilike(f"%{q}%"))
    return [{"id":d.id,"filename":d.filename,"reference":p.reference,"proposal_title":p.title,"version":d.version,"uploaded_at":d.uploaded_at,"content_type":d.content_type} for d,p in s.execute(st).all()]
@app.get("/documents/{did}/download")
def download(did:int,u=Depends(current),s:Session=Depends(db)):
    d=s.get(Document,did)
    if not d or not (UPLOAD_DIR/d.stored_name).is_file(): raise HTTPException(404,"Document not found")
    p=s.get(Proposal,d.proposal_id)
    if not p or not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this document")
    audit(s,u,"Downloaded","document",did);s.commit();return FileResponse(UPLOAD_DIR/d.stored_name,media_type=d.content_type,filename=d.filename)
@app.post("/proposals/{pid}/assignments")
def assign(pid:int,body:AssignmentIn,u=Depends(allow("Admin")),s:Session=Depends(db)):
    if not s.get(Proposal,pid) or not s.get(User,body.user_id): raise HTTPException(404,"Proposal or user not found")
    existing=s.scalar(select(Assignment).where(Assignment.proposal_id==pid,Assignment.user_id==body.user_id))
    if existing: existing.role=body.role
    else: s.add(Assignment(proposal_id=pid,**body.model_dump()))
    notify(s,body.user_id,f"You were assigned to proposal #{pid} as {body.role}");audit(s,u,"Assigned","proposal",pid,body.role);s.commit();return {"ok":True}
@app.get("/notifications")
def notifications(u=Depends(current),s:Session=Depends(db)):
    return [{"id":x.id,"message":x.message,"read":x.read,"created_at":x.created_at} for x in s.scalars(select(Notification).where(Notification.user_id==u.id).order_by(Notification.created_at.desc())).all()]
@app.post("/notifications/{nid}/read")
def read_notification(nid:int,u=Depends(current),s:Session=Depends(db)):
    n=s.get(Notification,nid)
    if not n or n.user_id!=u.id: raise HTTPException(404,"Notification not found")
    n.read=True;s.commit();return {"ok":True}
@app.get("/users")
def users(u=Depends(allow("Admin")),s:Session=Depends(db)): return [user_dict(x) for x in s.scalars(select(User).order_by(User.name)).all()]
@app.post("/users")
def create_user(body:UserIn,u=Depends(allow("Admin")),s:Session=Depends(db)):
    if body.role not in ROLES: raise HTTPException(422,"Unknown role")
    if s.scalar(select(User).where(User.email==body.email)): raise HTTPException(409,"Email already exists")
    if not body.password: raise HTTPException(422,"A password is required")
    x=User(name=body.name,email=body.email,role=body.role,password_hash=pwd.hash(body.password),department_id=body.department_id,active=body.active);s.add(x);s.flush();audit(s,u,"Created","user",x.id);s.commit();return user_dict(x)
@app.put("/users/{uid}")
def update_user(uid:int,body:UserIn,u=Depends(allow("Admin")),s:Session=Depends(db)):
    x=s.get(User,uid)
    if not x: raise HTTPException(404,"User not found")
    if body.role not in ROLES: raise HTTPException(422,"Unknown role")
    if uid==u.id and not body.active: raise HTTPException(409,"You cannot deactivate your own account")
    x.name,x.email,x.role,x.department_id,x.active=body.name,body.email,body.role,body.department_id,body.active
    if body.password:x.password_hash=pwd.hash(body.password)
    audit(s,u,"Updated","user",uid);s.commit();return user_dict(x)
@app.get("/reports/proposals.csv")
def export_csv(u=Depends(current),s:Session=Depends(db)):
    out=io.StringIO();w=csv.writer(out);w.writerow(["Reference","Title","Category","Priority","Status","Decision","Outcome","Created"])
    for p in s.scalars(select(Proposal).order_by(Proposal.created_at.desc())).all():w.writerow([p.reference,p.title,p.category,p.priority,p.status,p.decision or "",p.outcome or "",p.created_at.isoformat()])
    audit(s,u,"Exported","report",0);s.commit();return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=ipmprs-proposals.csv"})
@app.get("/audit")
def audits(u=Depends(allow("Admin")),s:Session=Depends(db)): return [{"action":x.action,"entity":x.entity,"entity_id":x.entity_id,"details":x.details,"created_at":x.created_at} for x in s.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(100)).all()]
