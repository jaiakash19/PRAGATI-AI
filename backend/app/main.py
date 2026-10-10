"""IPMPRS API: authenticated proposal workflow and precedent retrieval."""
import csv, hashlib, io, os, re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text, JSON, create_engine, select, func, text, or_
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
    __tablename__="documents"; id: Mapped[int]=mapped_column(primary_key=True); proposal_id: Mapped[int]=mapped_column(ForeignKey("proposals.id")); filename: Mapped[str]=mapped_column(String(255)); stored_name: Mapped[str]=mapped_column(String(255)); content_type: Mapped[str]=mapped_column(String(100)); extracted_text: Mapped[str]=mapped_column(Text, default=""); content_blob: Mapped[Optional[bytes]]=mapped_column(LargeBinary, nullable=True); document_type: Mapped[str]=mapped_column(String(50), default="Supporting Document"); ocr_status: Mapped[str]=mapped_column(String(40), default="not_required"); version: Mapped[int]=mapped_column(Integer, default=1); uploaded_at: Mapped[datetime]=mapped_column(DateTime, default=lambda:datetime.now(timezone.utc)); proposal: Mapped[Proposal]=relationship(back_populates="documents")
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
class PrecedentPreviewIn(BaseModel):
    title:str=Field(min_length=3,max_length=240)
    summary:str=Field(min_length=10,max_length=10000)
    category:str=Field(min_length=2,max_length=80)
    priority:str="Medium"

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
def visible_to(u):
    """SQL predicate for listing proposals visible to a submitter."""
    if u.role == "Submitter":
        return or_(Proposal.author_id == u.id, Proposal.id.in_(select(Assignment.proposal_id).where(Assignment.user_id == u.id)))
    return True

def assignment_allows(s, u, p):
    assignments=list(s.scalars(select(Assignment).where(Assignment.proposal_id==p.id)).all())
    return not assignments or any(a.user_id==u.id for a in assignments)
def proposal_dict(p): return {"id":p.id,"reference":p.reference,"title":p.title,"summary":p.summary,"category":p.category,"priority":p.priority,"status":p.status,"created_at":p.created_at,"decision":p.decision,"observations":p.observations,"outcome":p.outcome}
def user_dict(x): return {"id":x.id,"name":x.name,"email":x.email,"role":x.role,"department_id":x.department_id,"active":x.active}
def words(t): return set(re.findall(r"[a-z]{3,}",t.lower()))
def score(query, p):
    """Explainable lexical fallback including recorded decisions, outcomes and extracted case-file text."""
    parts = [p.title, p.summary, p.category, p.decision or "", p.observations or "", p.outcome or ""]
    try:
        parts.extend(d.extracted_text for d in p.documents if d.extracted_text)
    except Exception:
        pass
    a, b = words(query), words(" ".join(parts))
    return round(100 * len(a & b) / max(1, len(a | b)), 1)
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
def proposal_embedding_text(p):
    """Canonical text representation used consistently for proposal embeddings."""
    return "\n".join([p.title, p.summary, p.category, p.decision or "", p.observations or "", p.outcome or ""] + [f"Document type: {d.document_type}\nDocument: {d.filename}\n{d.extracted_text}" for d in p.documents]).strip()

def store_embedding(s, p):
    source=proposal_embedding_text(p)
    vector=embedding(source)
    if not vector: return False
    digest=hashlib.sha256(source.encode()).hexdigest(); record=s.scalar(select(ProposalEmbedding).where(ProposalEmbedding.proposal_id==p.id))
    if record: record.vector,record.source_hash,record.created_at=vector,digest,datetime.now(timezone.utc)
    else: s.add(ProposalEmbedding(proposal_id=p.id,model="all-MiniLM-L6-v2",vector=vector,source_hash=digest))
    return True
def extract_document_text(raw, content_type):
    """Extract text and OCR image-only pages. Returns (text, status)."""
    ct = (content_type or "").lower().split(";")[0].strip()
    try:
        if ct == "text/plain":
            value = raw.decode("utf-8", errors="replace").strip()
            return value, "text_extracted" if value else "no_text_detected"
        if ct == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            from docx import Document as WordDocument
            doc = WordDocument(io.BytesIO(raw))
            parts = [p.text for p in doc.paragraphs if p.text.strip()]
            for table in doc.tables:
                for row in table.rows:
                    parts.append(" | ".join(cell.text.strip() for cell in row.cells if cell.text.strip()))
            value = "\n".join(parts).strip()
            return value, "text_extracted" if value else "no_text_detected"
        if ct in {"image/jpeg", "image/jpg", "image/png", "image/webp", "image/tiff", "image/bmp"}:
            try:
                from PIL import Image, ImageOps
                import pytesseract
                with Image.open(io.BytesIO(raw)) as opened:
                    if opened.width * opened.height > 30_000_000:
                        return "", "image_dimensions_too_large"
                    image = ImageOps.exif_transpose(opened).convert("RGB")
                    image.thumbnail((2400, 2400))
                    value = pytesseract.image_to_string(image, lang="eng").strip()
                return value, "ocr_processed" if value else "no_text_detected"
            except Exception:
                return "", "ocr_unavailable"
        if ct == "application/pdf":
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(raw))
            pages = []
            needs_ocr = []
            for index, page in enumerate(reader.pages):
                value = (page.extract_text() or "").strip()
                pages.append(value)
                if len(value) < 35:
                    needs_ocr.append(index)
            attempted = needs_ocr[:30]
            ocr_failed = False
            if attempted:
                try:
                    import pypdfium2 as pdfium
                    import pytesseract
                    pdf = pdfium.PdfDocument(raw)
                    for index in attempted:
                        page = pdf[index]
                        bitmap = page.render(scale=1.5)
                        image = bitmap.to_pil()
                        try:
                            value = pytesseract.image_to_string(image, lang="eng").strip()
                            if value:
                                pages[index] = value
                        finally:
                            image.close()
                            bitmap.close()
                            page.close()
                    pdf.close()
                except Exception:
                    ocr_failed = True
            combined = "\n\n".join(x for x in pages if x).strip()
            if ocr_failed and not combined:
                return "", "ocr_unavailable"
            if attempted and len(needs_ocr) > len(attempted):
                return combined, "ocr_partial"
            if attempted and not ocr_failed:
                return combined, "ocr_processed" if combined else "no_text_detected"
            return combined, "text_extracted" if combined else ("ocr_unavailable" if ocr_failed else "no_text_detected")
    except Exception:
        return "", "extraction_failed"
    return "", "unsupported_type"


def extract_text(raw, content_type):
    """Compatibility wrapper returning extracted text only."""
    return extract_document_text(raw, content_type)[0]


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
    scope = visible_to(u)
    total=s.scalar(select(func.count(Proposal.id)).where(scope)) or 0
    rows=s.scalars(select(Proposal).where(scope).order_by(Proposal.updated_at.desc()).limit(6)).all()
    return {"stats":{"total":total,"pending":s.scalar(select(func.count(Proposal.id)).where(scope,Proposal.status.in_(["Submitted","Under Review","Recommended"]))) or 0,"approved":s.scalar(select(func.count(Proposal.id)).where(scope,Proposal.status.in_(["Approved","Implemented","Closed"]))) or 0,"implemented":s.scalar(select(func.count(Proposal.id)).where(scope,Proposal.status.in_(["Implemented","Closed"]))) or 0},"recent":[proposal_dict(x) for x in rows]}
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
    r=proposal_dict(p);r["documents"]=[{"id":d.id,"filename":d.filename,"version":d.version,"uploaded_at":d.uploaded_at,"content_type":d.content_type,"document_type":d.document_type,"ocr_status":d.ocr_status,"extracted_text_length":len(d.extracted_text or "")} for d in p.documents];r["reviews"]=[{"action":x.action,"reason":x.reason,"created_at":x.created_at} for x in s.scalars(select(Review).where(Review.proposal_id==pid)).all()]; impl=s.scalar(select(Implementation).where(Implementation.proposal_id==pid));r["implementation"]={"progress":impl.progress,"milestone":impl.milestone,"evidence":impl.evidence,"closed_at":impl.closed_at} if impl else None;r["assignments"]=[{"id":a.id,"user_id":a.user_id,"role":a.role} for a in s.scalars(select(Assignment).where(Assignment.proposal_id==pid)).all()];return r
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
    p.status=new;p.decision=body.action.title() if body.action in {"approve","reject"} else p.decision;p.observations=body.reason;p.updated_at=datetime.now(timezone.utc);s.add(Review(proposal_id=pid,reviewer_id=u.id,action=body.action,reason=body.reason)); notify(s,p.author_id,f"{p.reference}: {new}. {body.reason}");store_embedding(s,p);audit(s,u,body.action,"proposal",pid,body.reason);s.commit();return proposal_dict(p)
def retrieve_precedents(s:Session, query:str, exclude_id:Optional[int]=None, limit:int=10):
    """Retrieve institutionally relevant historical records; never silently discard rejected/modified cases."""
    filters=[Proposal.status!="Draft"]
    if exclude_id is not None: filters.append(Proposal.id!=exclude_id)
    candidates=s.scalars(select(Proposal).where(*filters)).all()
    qv=embedding(query)
    if qv and DATABASE_URL.startswith("postgresql"):
        try:
            rows=s.execute(
                select(Proposal,ProposalEmbedding.vector.cosine_distance(qv).label("distance"))
                .join(ProposalEmbedding,ProposalEmbedding.proposal_id==Proposal.id)
                .where(*filters).order_by("distance").limit(limit)
            ).all()
            if rows:
                items=[]
                for proposal,distance in rows:
                    department=s.get(Department,proposal.department_id) if proposal.department_id else None
                    excerpt=(proposal.summary+"\nDecision: "+(proposal.decision or "Not recorded")
                        +"\nObservations: "+(proposal.observations or "Not recorded")
                        +"\nOutcome: "+(proposal.outcome or "Not recorded"))
                    items.append({**proposal_dict(proposal),"department_name":department.name if department else "Unspecified",
                        "similarity":round(max(0,100*(1-float(distance))),1),"matched_excerpt":excerpt[:520],
                        "method":"semantic pgvector"})
                return items
        except Exception:
            s.rollback()
    items=[]
    for proposal in sorted(candidates,key=lambda item:score(query,item),reverse=True)[:limit]:
        department=s.get(Department,proposal.department_id) if proposal.department_id else None
        excerpt=(proposal.summary+"\nDecision: "+(proposal.decision or "Not recorded")
            +"\nObservations: "+(proposal.observations or "Not recorded")
            +"\nOutcome: "+(proposal.outcome or "Not recorded"))
        items.append({**proposal_dict(proposal),"department_name":department.name if department else "Unspecified",
            "similarity":score(query,proposal),"matched_excerpt":excerpt[:520],"method":"lexical fallback"})
    return items


def build_impact_brief(s:Session, matches:list):
    """Transparent screening cues, not a calibrated probability or an automated decision."""
    semantic=bool(matches and matches[0].get("method")=="semantic pgvector")
    threshold=50 if semantic else 5
    relevant=[m for m in matches if float(m.get("similarity") or 0)>=threshold]
    adverse_statuses={"Rejected","Modifications Requested","Returned"}
    positive_statuses={"Approved","Implemented","Closed"}
    adverse=[m for m in relevant if m.get("status") in adverse_statuses or str(m.get("decision") or "").lower().startswith("reject")]
    positive=[m for m in relevant if m.get("status") in positive_statuses and not str(m.get("decision") or "").lower().startswith("reject")]
    conflicting=bool(adverse and positive)
    ids=[int(m["id"]) for m in relevant if m.get("id") is not None]
    review_rows=s.scalars(select(Review).where(Review.proposal_id.in_(ids)).order_by(Review.created_at.desc())).all() if ids else []
    reason_parts=[str(m.get(k) or "") for m in relevant for k in ("observations","outcome","decision")]
    reason_parts.extend(x.reason for x in review_rows)
    evidence_text=" ".join(reason_parts).lower()
    recurring_terms=["privacy","security","budget","cost","training","maintenance","staffing","procurement","delay","compliance","retention","access","evidence","deployment","reliability","feasibility","safety","funding","timeline","integration","data quality","interoperability"]
    concerns=[term for term in recurring_terms if evidence_text.count(term)>=2]
    missing_outcomes=[{"reference":m.get("reference"),"title":m.get("title"),"status":m.get("status")} for m in positive if not str(m.get("outcome") or "").strip()]
    departments=sorted({m.get("department_name") for m in relevant if m.get("department_name")})
    if len(adverse)>=2:
        signal="Elevated review"
        basis=f"{len(adverse)} relevant records have a rejected, returned or modifications-requested status."
    elif adverse or conflicting:
        signal="Review required"
        basis="At least one relevant adverse precedent exists; compare its recorded reason with the current proposal."
    elif positive:
        signal="No adverse precedent found"
        basis="Relevant successful precedents were found, but this does not prove the current proposal is safe or suitable."
    else:
        signal="Insufficient historical evidence"
        basis="No sufficiently similar indexed record crossed the screening threshold."
    checks=[]
    if adverse: checks.append("Read the original rejection/return/modification reasons and show how the current proposal addresses them.")
    if conflicting: checks.append("The archive contains both successful and adverse precedents; compare their assumptions, scope and implementation conditions.")
    if positive: checks.append("Compare intended benefits with the recorded implementation outcomes of the successful precedents.")
    if missing_outcomes: checks.append("Some comparable approved/closed records lack a recorded outcome; verify whether the intended benefits were actually delivered.")
    if concerns: checks.append("Check recurring recorded concerns: "+", ".join(concerns)+".")
    if not checks: checks.append("Confirm with the relevant departments whether additional historical files or decisions exist before reaching a decision.")
    return {
        "signal_level":signal,
        "basis":basis,
        "relevant_records_examined":len(relevant),
        "adverse_precedents":[{"reference":m.get("reference"),"title":m.get("title"),"status":m.get("status"),"decision":m.get("decision"),"observations":m.get("observations"),"similarity":m.get("similarity")} for m in adverse[:5]],
        "successful_precedents":[{"reference":m.get("reference"),"title":m.get("title"),"status":m.get("status"),"decision":m.get("decision"),"outcome":m.get("outcome"),"similarity":m.get("similarity")} for m in positive[:5]],
        "conflicting_precedents":conflicting,
        "recurring_concerns":concerns,
        "missing_outcomes":missing_outcomes[:5],
        "departments_represented":departments,
        "checks_before_decision":checks,
        "disclaimer":"This is an explainable screening aid based on recorded historical data and similarity. It is not a calibrated risk probability, a legal assessment, or an automated recommendation to approve or reject. Verify each source record."
    }


@app.post("/precedents/preview")
def preview_precedents(body:PrecedentPreviewIn,u=Depends(current),s:Session=Depends(db)):
    query="\n".join([body.title,body.summary,body.category,body.priority])
    matches=retrieve_precedents(s,query,limit=10)
    return {"query":query,"method":matches[0]["method"] if matches else ("semantic pgvector" if embedding(query) and DATABASE_URL.startswith("postgresql") else "lexical fallback"),
        "matches":matches,"impact_brief":build_impact_brief(s,matches)}


@app.get("/proposals/{pid}/impact-brief")
def proposal_impact_brief(pid:int,u=Depends(current),s:Session=Depends(db)):
    p=s.get(Proposal,pid)
    if not p: raise HTTPException(404,"Proposal not found")
    if not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this proposal")
    query="\n".join([p.title,p.summary,p.category,p.decision or "",p.observations or "",p.outcome or ""])
    matches=retrieve_precedents(s,query,exclude_id=pid,limit=10)
    return {"proposal_reference":p.reference,"method":matches[0]["method"] if matches else "no_matches",
        "matches":matches,"impact_brief":build_impact_brief(s,matches)}


@app.get("/proposals/{pid}/precedents")
def precedents(pid:int,u=Depends(current),s:Session=Depends(db)):
    p=s.get(Proposal,pid)
    if not p:raise HTTPException(404,"Proposal not found")
    if not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this proposal")
    query="\n".join([p.title,p.summary,p.category,p.decision or "",p.observations or "",p.outcome or ""])
    return retrieve_precedents(s,query,exclude_id=pid,limit=10)
@app.post("/admin/reindex-embeddings")
def reindex_embeddings(u=Depends(allow("Admin")),s:Session=Depends(db)):
    """Batch-rebuild the historical proposal vector index after imports or model setup."""
    global _embedding_model
    proposals=s.scalars(select(Proposal).order_by(Proposal.id)).all()
    if not proposals:
        return {"indexed":0,"total":0,"remaining":0,"model":"all-MiniLM-L6-v2","message":"No proposals are available to index."}
    try:
        if _embedding_model is None:
            from sentence_transformers import SentenceTransformer
            _embedding_model=SentenceTransformer("all-MiniLM-L6-v2")
        indexed=0
        batch_size=32
        for start in range(0,len(proposals),batch_size):
            batch=proposals[start:start+batch_size]
            sources=[proposal_embedding_text(p) for p in batch]
            vectors=_embedding_model.encode(sources,normalize_embeddings=True,batch_size=16)
            for p,source,vector in zip(batch,sources,vectors):
                digest=hashlib.sha256(source.encode()).hexdigest()
                record=s.scalar(select(ProposalEmbedding).where(ProposalEmbedding.proposal_id==p.id))
                values=vector.tolist() if hasattr(vector,"tolist") else list(vector)
                if record:
                    record.vector=values;record.source_hash=digest;record.model="all-MiniLM-L6-v2";record.created_at=datetime.now(timezone.utc)
                else:
                    s.add(ProposalEmbedding(proposal_id=p.id,model="all-MiniLM-L6-v2",vector=values,source_hash=digest))
                indexed+=1
            s.commit()
        return {"indexed":indexed,"total":len(proposals),"remaining":max(0,len(proposals)-indexed),
            "model":"all-MiniLM-L6-v2","dimensions":384,"message":"Historical proposal text, decisions, observations, outcomes and extracted document text have been embedded and indexed."}
    except Exception as exc:
        s.rollback()
        raise HTTPException(503,"Historical indexing could not complete. Ensure the sentence-transformers model can be downloaded/loaded, then retry. Details: "+str(exc)[:240])


@app.post("/proposals/{pid}/implementation")
def implementation(pid:int,body:ImplementationIn,u=Depends(allow("Implementation Officer","Admin")),s:Session=Depends(db)):
    p=s.get(Proposal,pid)
    if not p:raise HTTPException(404,"Proposal not found")
    if p.status not in {"Approved","Implemented"}: raise HTTPException(409,"Implementation requires an approved proposal")
    if u.role != "Admin" and not assignment_allows(s,u,p): raise HTTPException(403,"Proposal is assigned to another officer")
    rec=s.scalar(select(Implementation).where(Implementation.proposal_id==pid)) or Implementation(proposal_id=pid);rec.progress=body.progress;rec.milestone=body.milestone;rec.evidence=body.evidence
    if body.progress==100:rec.closed_at=datetime.now(timezone.utc);p.status="Closed";p.outcome=body.evidence
    else:p.status="Implemented"
    s.add(rec);store_embedding(s,p);audit(s,u,"Updated implementation","proposal",pid);s.commit();return {"progress":rec.progress,"status":p.status}
@app.post("/proposals/{pid}/documents")
def upload(pid:int,file:UploadFile=File(...),document_type:str=Form("Case File"),u=Depends(allow("Admin","Submitter")),s:Session=Depends(db)):
    content_type=(file.content_type or "").lower().split(";")[0].strip()
    extension=Path(file.filename or "").suffix.lower()
    allowed={
        ".pdf":{"application/pdf"},
        ".docx":{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        ".txt":{"text/plain"},
        ".jpg":{"image/jpeg","image/jpg"}, ".jpeg":{"image/jpeg","image/jpg"},
        ".png":{"image/png"}, ".webp":{"image/webp"},
        ".tif":{"image/tiff"}, ".tiff":{"image/tiff"}, ".bmp":{"image/bmp"},
    }
    if extension not in allowed or content_type not in allowed[extension]:
        raise HTTPException(415,"Allowed types: PDF, DOCX, TXT, JPG/JPEG, PNG, WEBP, TIFF and BMP. Filename extension and MIME type must match.")
    if document_type not in {"Case File","Supporting Document","Photo/Scan","Evidence Attachment"}: raise HTTPException(422,"Unknown document type.")
    p=s.get(Proposal,pid)
    if not p: raise HTTPException(404,"Proposal not found")
    if not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this proposal")
    raw=file.file.read()
    if not raw: raise HTTPException(400,"The uploaded file is empty.")
    if len(raw)>10_000_000: raise HTTPException(413,"File too large; maximum is 10 MB.")
    extracted, extraction_status=extract_document_text(raw,content_type)
    original_name=Path(file.filename or "case-file").name[:240]
    stored=hashlib.sha256(raw).hexdigest()+extension
    try: (UPLOAD_DIR/stored).write_bytes(raw)
    except OSError: raise HTTPException(500,"The original file could not be persisted.")
    d=Document(proposal_id=pid,filename=original_name,stored_name=stored,content_type=content_type,extracted_text=extracted,content_blob=raw,document_type=document_type,ocr_status=extraction_status)
    s.add(d);s.flush();store_embedding(s,p)
    audit(s,u,"Uploaded and digitized case file","document",d.id,f"type={document_type}; filename={original_name}; extraction={extraction_status}; chars={len(extracted)}")
    s.commit()
    return {"id":d.id,"filename":d.filename,"document_type":d.document_type,"extraction_status":extraction_status,"extracted_characters":len(extracted),"saved_in_database":True,"searchable":bool(extracted),"message":("File and extracted text saved. OCR completed." if extraction_status in {"ocr_processed","ocr_partial"} else "File saved, but no searchable text was extracted. Verify OCR status and scan quality." if not extracted else "File and extracted text saved and searchable.")}

@app.get("/documents")
def documents(q:str="",u=Depends(current),s:Session=Depends(db)):
    st=select(Document,Proposal).join(Proposal,Document.proposal_id==Proposal.id).where(visible_to(u)).order_by(Document.uploaded_at.desc())
    if q: st=st.where(Document.filename.ilike(f"%{q}%") | Proposal.reference.ilike(f"%{q}%") | Document.extracted_text.ilike(f"%{q}%"))
    return [{"id":d.id,"filename":d.filename,"document_type":d.document_type,"ocr_status":d.ocr_status,"extracted_text_length":len(d.extracted_text or ""),"reference":p.reference,"proposal_title":p.title,"version":d.version,"uploaded_at":d.uploaded_at,"content_type":d.content_type} for d,p in s.execute(st).all()]
@app.get("/documents/{did}/download")
def download(did:int,u=Depends(current),s:Session=Depends(db)):
    d=s.get(Document,did)
    if not d: raise HTTPException(404,"Document not found")
    p=s.get(Proposal,d.proposal_id)
    if not p or not can_access_proposal(s,u,p): raise HTTPException(403,"Not authorized for this document")
    audit(s,u,"Downloaded","document",did);s.commit()
    safe_name=re.sub(r"[^A-Za-z0-9._-]","_",Path(d.filename).name)[:180] or "case-file"
    if d.content_blob is not None:
        return Response(content=d.content_blob,media_type=d.content_type,headers={"Content-Disposition":f'attachment; filename="{safe_name}"',"X-Content-Type-Options":"nosniff"})
    if not (UPLOAD_DIR/d.stored_name).is_file(): raise HTTPException(404,"Stored file is unavailable")
    return FileResponse(UPLOAD_DIR/d.stored_name,media_type=d.content_type,filename=safe_name)
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
    for p in s.scalars(select(Proposal).where(visible_to(u)).order_by(Proposal.created_at.desc())).all():w.writerow([p.reference,p.title,p.category,p.priority,p.status,p.decision or "",p.outcome or "",p.created_at.isoformat()])
    audit(s,u,"Exported","report",0);s.commit();return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=ipmprs-proposals.csv"})
@app.get("/audit")
def audits(u=Depends(allow("Admin")),s:Session=Depends(db)): return [{"action":x.action,"entity":x.entity,"entity_id":x.entity_id,"details":x.details,"created_at":x.created_at} for x in s.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(100)).all()]
