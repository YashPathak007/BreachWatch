import logging, json
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session
from .config import get_settings
from .db import Base, engine, get_db
from .detection import evaluate_event, validate_rule_config
from .models import Alert, AlertEvent, AlertStatus, AuditLog, DetectionRule, InvestigationNote, Role, SecurityEvent, User
from .schemas import EventIn, EventOut, LoginIn, NoteIn, RegisterIn, RuleUpdate, StatusIn, TokenOut, UserOut
from .security import create_access_token, current_user, hash_password, require_roles, verify_password

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("breachwatch")
settings = get_settings()
app = FastAPI(title="BreachWatch API", version="1.0.0", description="Defensive security monitoring and investigation API")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.cors_origins.split(",")], allow_credentials=True, allow_methods=["GET","POST","PATCH"], allow_headers=["Authorization","Content-Type"])

@app.on_event("startup")
def startup(): Base.metadata.create_all(bind=engine)

def audit(db, actor, action, resource_type, resource_id=None, details=None, request=None):
    db.add(AuditLog(actor_id=actor.id if actor else None, action=action, resource_type=resource_type, resource_id=str(resource_id) if resource_id else None, details=details or {}, ip_address=request.client.host if request and request.client else None))
    logger.info(json.dumps({"action": action, "resource_type": resource_type, "resource_id": resource_id, "actor_id": actor.id if actor else None}))

def event_out(event):
    return {"id":event.id,"timestamp":event.timestamp,"source":event.source,"event_type":event.event_type,"severity":event.severity,"username":event.username,"source_ip":event.source_ip,"destination_ip":event.destination_ip,"hostname":event.hostname,"application":event.application,"action":event.action,"status":event.status,"message":event.message,"metadata":event.metadata_json,"raw_event":event.raw_event,"created_at":event.created_at}

def alert_out(db, alert):
    events = db.scalars(select(SecurityEvent).join(AlertEvent, AlertEvent.event_id == SecurityEvent.id).where(AlertEvent.alert_id == alert.id).order_by(SecurityEvent.timestamp)).all()
    notes = db.scalars(select(InvestigationNote).where(InvestigationNote.alert_id == alert.id).order_by(InvestigationNote.created_at)).all()
    return {"id":alert.id,"title":alert.title,"severity":alert.severity,"status":alert.status,"explanation":alert.explanation,"recommended_action":alert.recommended_action,"source_ip":alert.source_ip,"username":alert.username,"first_seen":alert.first_seen,"last_seen":alert.last_seen,"created_at":alert.created_at,"rule":{"id":alert.rule.id,"key":alert.rule.rule_key,"name":alert.rule.name},"assigned_to": {"id":alert.assignee.id,"name":alert.assignee.full_name} if alert.assignee else None,"events":[event_out(e) for e in events],"notes":[{"id":n.id,"content":n.content,"author":n.author.full_name,"created_at":n.created_at} for n in notes]}


def rule_out(rule):
    return {"id": rule.id, "rule_key": rule.rule_key, "name": rule.name, "description": rule.description, "enabled": rule.enabled, "severity": rule.severity, "config": rule.config or {}, "updated_at": rule.updated_at}


def persist_event(db, payload: EventIn, request: Request, user: User):
    """Persist one event and its detections; the caller owns the transaction."""
    event = SecurityEvent(timestamp=payload.timestamp or datetime.now(timezone.utc), source=payload.source, event_type=payload.event_type, severity=payload.severity.value, username=payload.username, source_ip=payload.source_ip, destination_ip=payload.destination_ip, hostname=payload.hostname, application=payload.application, action=payload.action, status=payload.status, message=payload.message, metadata_json=payload.metadata, raw_event=payload.raw_event or payload.model_dump(mode="json"))
    db.add(event); db.flush(); alerts = evaluate_event(db, event)
    for alert in alerts: audit(db, None, "alert.created", "alert", alert.id, {"rule":alert.rule.rule_key}, request)
    audit(db, user, "event.ingested", "event", event.id, {"event_type":event.event_type}, request)
    return {"event": event_out(event), "alerts_created": [a.id for a in alerts]}

@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1")); redis_ok = False
    try:
        import redis; redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1).ping(); redis_ok = True
    except Exception: pass
    return {"status":"ok","database":"ok","redis":"ok" if redis_ok else "unavailable"}

@app.post("/api/auth/register", response_model=TokenOut)
def register(payload: RegisterIn, request: Request, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == payload.email.lower())): raise HTTPException(409, "Email is already registered")
    user = User(email=payload.email.lower(), full_name=payload.full_name, password_hash=hash_password(payload.password), role=Role.VIEWER.value)
    db.add(user); db.flush(); audit(db, user, "user.registered", "user", user.id, request=request); db.commit()
    return {"access_token":create_access_token(user),"user":user}

@app.post("/api/auth/login", response_model=TokenOut)
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        audit(db, user, "auth.login_failed", "user", user.id if user else None, {"email":payload.email.lower()}, request); db.commit(); raise HTTPException(401, "Invalid email or password")
    audit(db, user, "auth.login", "user", user.id, request=request); db.commit()
    return {"access_token":create_access_token(user),"user":user}

@app.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)): return user

@app.post("/api/events")
def ingest(payload: EventIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST))):
    result = persist_event(db, payload, request, user); db.commit(); return result

@app.post("/api/events/demo")
def generate_demo_events(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST))):
    """Generate a bounded synthetic sequence through the same ingestion path."""
    now = datetime.now(timezone.utc)
    payloads = [EventIn(timestamp=now - timedelta(minutes=4) + timedelta(seconds=index * 30), source="demo-auth", event_type="authentication", severity="MEDIUM", username="sam.operator", source_ip="198.51.100.42", application="identity-service", action="login", status="failure", message="Synthetic failed login for demonstration", metadata={"synthetic": True}) for index in range(5)]
    payloads.append(EventIn(timestamp=now, source="demo-auth", event_type="authentication", severity="HIGH", username="sam.operator", source_ip="198.51.100.42", application="identity-service", action="login", status="success", message="Synthetic successful login after failures", metadata={"synthetic": True}))
    created, alert_ids = [], []
    for payload in payloads:
        result = persist_event(db, payload, request, user)
        created.append(result["event"]["id"]); alert_ids.extend(result["alerts_created"])
    audit(db, user, "events.demo_generated", "event", created[-1], {"count": len(created), "synthetic": True}, request); db.commit()
    return {"events_created": len(created), "alerts_created": alert_ids}

@app.post("/api/events/log-file")
async def ingest_log_file(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(require_roles(Role.ADMIN, Role.ANALYST))):
    """Parse documented JSON-lines logs; every line must be a valid EventIn payload."""
    if not file.filename or not file.filename.lower().endswith((".jsonl", ".log")):
        raise HTTPException(400, "Upload a .jsonl or .log file")
    content = await file.read(2_000_001)
    if len(content) > 2_000_000: raise HTTPException(413, "Log file exceeds the 2 MB limit")
    try: lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc: raise HTTPException(422, "Log file must be UTF-8 encoded") from exc
    payloads = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip(): continue
        try: payload = EventIn.model_validate(json.loads(line))
        except (json.JSONDecodeError, ValueError) as exc: raise HTTPException(422, f"Invalid JSON event on line {line_number}") from exc
        payloads.append(payload)
    if not payloads: raise HTTPException(422, "Log file must contain at least one event")
    created, alerts = [], []
    try:
        for payload in payloads:
            result = persist_event(db, payload, request, user); created.append(result["event"]["id"]); alerts.extend(result["alerts_created"])
        audit(db, user, "events.log_file_ingested", "event", created[-1], {"filename": file.filename, "count": len(created)}, request); db.commit()
    except Exception:
        db.rollback()
        raise
    return {"events_created": len(created), "alerts_created": alerts, "filename": file.filename}

@app.get("/api/events")
def list_events(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100), search: str | None = None, severity: str | None = None, event_type: str | None = None, source_ip: str | None = None, username: str | None = None, db: Session = Depends(get_db), user: User = Depends(current_user)):
    q = select(SecurityEvent); filters=[]
    if search: filters.append((SecurityEvent.message.ilike(f"%{search}%")) | (SecurityEvent.event_type.ilike(f"%{search}%")) | (SecurityEvent.source_ip.ilike(f"%{search}%")) | (SecurityEvent.username.ilike(f"%{search}%")))
    if severity: filters.append(SecurityEvent.severity == severity)
    if event_type: filters.append(SecurityEvent.event_type == event_type)
    if source_ip: filters.append(SecurityEvent.source_ip == source_ip)
    if username: filters.append(SecurityEvent.username == username)
    total = db.scalar(select(func.count()).select_from(SecurityEvent).where(*filters))
    rows = db.scalars(q.where(*filters).order_by(desc(SecurityEvent.timestamp)).offset((page-1)*page_size).limit(page_size)).all()
    return {"items":[event_out(e) for e in rows],"total":total,"page":page,"page_size":page_size}

@app.get("/api/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    event=db.get(SecurityEvent,event_id)
    if not event: raise HTTPException(404,"Event not found")
    return event_out(event)

@app.get("/api/alerts")
def list_alerts(status: str | None=None, severity: str | None=None, search: str | None=None, db: Session=Depends(get_db), user: User=Depends(current_user)):
    q=select(Alert).order_by(desc(Alert.last_seen)); filters=[]
    if status: filters.append(Alert.status==status)
    if severity: filters.append(Alert.severity==severity)
    if search: filters.append((Alert.title.ilike(f"%{search}%")) | (Alert.explanation.ilike(f"%{search}%")))
    return {"items":[alert_out(db,a) for a in db.scalars(q.where(*filters)).all()]}

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id:int, db:Session=Depends(get_db), user:User=Depends(current_user)):
    alert=db.get(Alert,alert_id)
    if not alert: raise HTTPException(404,"Alert not found")
    return alert_out(db,alert)

@app.patch("/api/alerts/{alert_id}/status")
def update_status(alert_id:int, payload:StatusIn, request:Request, db:Session=Depends(get_db), user:User=Depends(require_roles(Role.ADMIN,Role.ANALYST))):
    alert=db.get(Alert,alert_id)
    if not alert: raise HTTPException(404,"Alert not found")
    old=alert.status; alert.status=payload.status.value; audit(db,user,"alert.status_changed","alert",alert.id,{"from":old,"to":alert.status},request); db.commit(); return alert_out(db,alert)

@app.post("/api/alerts/{alert_id}/notes")
def add_note(alert_id:int, payload:NoteIn, request:Request, db:Session=Depends(get_db), user:User=Depends(require_roles(Role.ADMIN,Role.ANALYST))):
    if not db.get(Alert,alert_id): raise HTTPException(404,"Alert not found")
    note=InvestigationNote(alert_id=alert_id,author_id=user.id,content=payload.content); db.add(note); audit(db,user,"investigation.note_added","alert",alert_id,request=request); db.commit(); return {"id":note.id,"content":note.content,"author":user.full_name,"created_at":note.created_at}

@app.get("/api/rules")
def rules(db:Session=Depends(get_db), user:User=Depends(current_user)): return [rule_out(rule) for rule in db.scalars(select(DetectionRule).order_by(DetectionRule.id)).all()]
@app.patch("/api/rules/{rule_id}")
def update_rule(rule_id:int,payload:RuleUpdate,request:Request,db:Session=Depends(get_db),user:User=Depends(require_roles(Role.ADMIN))):
    rule=db.get(DetectionRule,rule_id)
    if not rule: raise HTTPException(404,"Rule not found")
    if payload.enabled is not None: rule.enabled=payload.enabled
    if payload.config is not None:
        merged = {**(rule.config or {}), **payload.config}
        try: rule.config = validate_rule_config(rule.rule_key, merged)
        except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    audit(db,user,"rule.updated","rule",rule.id,request=request); db.commit(); return rule_out(rule)

@app.get("/api/dashboard")
def dashboard(db:Session=Depends(get_db), user:User=Depends(current_user)):
    total_events=db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    current_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    trend_buckets = [current_hour - timedelta(hours=offset) for offset in range(23, -1, -1)]
    trend = {bucket: 0 for bucket in trend_buckets}
    timestamps = db.scalars(select(SecurityEvent.timestamp).where(SecurityEvent.timestamp >= trend_buckets[0], SecurityEvent.timestamp < current_hour + timedelta(hours=1))).all()
    for timestamp in timestamps:
        if timestamp.tzinfo is None: timestamp = timestamp.replace(tzinfo=timezone.utc)
        bucket = timestamp.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        if bucket in trend: trend[bucket] += 1
    def counts(column): return [{"name":row[0],"value":row[1]} for row in db.execute(select(column,func.count()).group_by(column)).all() if row[0]]
    recent_alerts=db.scalars(select(Alert).order_by(desc(Alert.created_at)).limit(5)).all(); recent_events=db.scalars(select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(8)).all()
    return {"total_events":total_events,"total_alerts":db.scalar(select(func.count()).select_from(Alert)) or 0,"open_alerts":db.scalar(select(func.count()).select_from(Alert).where(Alert.status.in_(["NEW","ACKNOWLEDGED","INVESTIGATING"]))) or 0,"detection_rule_count":db.scalar(select(func.count()).select_from(DetectionRule).where(DetectionRule.enabled.is_(True))) or 0,"events_over_time":[{"name":bucket.strftime("%H:%M"),"value":value} for bucket,value in trend.items()],"alerts_by_severity":counts(Alert.severity),"alerts_by_status":counts(Alert.status),"top_source_ips":counts(SecurityEvent.source_ip),"top_usernames":counts(SecurityEvent.username),"recent_alerts":[alert_out(db,a) for a in recent_alerts],"recent_events":[event_out(e) for e in recent_events]}

@app.get("/api/audit")
def audit_logs(db:Session=Depends(get_db), user:User=Depends(require_roles(Role.ADMIN,Role.ANALYST))):
    rows=db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(100)).all(); return [{"id":r.id,"action":r.action,"resource_type":r.resource_type,"resource_id":r.resource_id,"actor":r.actor.full_name if r.actor else "system","details":r.details,"created_at":r.created_at} for r in rows]
