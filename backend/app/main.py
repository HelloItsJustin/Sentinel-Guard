from __future__ import annotations

import os

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, select, text as sql_text
from sqlalchemy.orm import Session

from .classifiers.rules import classify_text
from .database import Base, engine
from .deps import get_db
from .models import Incident
from .schemas import AnalyzeRequest, AnalyzeResponse, IncidentOut, ISSUE_DESCRIPTIONS, PolicyConfig
from .services.logging_service import log_incident, protected_original_for_audit
from .services.policy_engine import evaluate_policy, sanitize_text


load_dotenv()

Base.metadata.create_all(bind=engine)


def ensure_incident_schema() -> None:
    inspector = inspect(engine)
    if "incidents" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("incidents")}
    if "policy_snapshot" in columns:
        return

    with engine.begin() as conn:
        conn.execute(sql_text("ALTER TABLE incidents ADD COLUMN policy_snapshot TEXT"))


ensure_incident_schema()

app = FastAPI(title="SentinelGuard API", version="0.1.0")
active_policy = PolicyConfig()

allowed_origins = os.getenv("SENTINELGUARD_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/descriptions")
def get_descriptions() -> dict:
    """Returns descriptions of all issue types for UI tooltips"""
    return ISSUE_DESCRIPTIONS


@app.get("/policy", response_model=PolicyConfig)
def get_policy() -> PolicyConfig:
    return active_policy


@app.put("/policy", response_model=PolicyConfig)
def update_policy(policy: PolicyConfig) -> PolicyConfig:
    global active_policy
    active_policy = policy
    return active_policy


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, db: Session = Depends(get_db)) -> AnalyzeResponse:
    text = (req.text or "").strip()
    policy_snapshot = active_policy
    policy_config = policy_snapshot.model_dump()
    if not text:
        classification = {"issues": [], "risk_level": "LOW"}
        policy = {"decision": "ALLOW", "sanitized_text": ""}
        incident = log_incident(
            db,
            source=req.source,
            user_id=req.user_id,
            original_text=req.text or "",
            sanitized_text=policy["sanitized_text"],
            risk_level=classification["risk_level"],
            issues=classification["issues"],
            decision=policy["decision"],
            policy_snapshot=policy_config,
        )
        return AnalyzeResponse(
            risk_level=classification["risk_level"],
            issues=classification["issues"],
            decision=policy["decision"],
            sanitized_text=policy["sanitized_text"],
            incident_id=incident.id,
        )

    classification = classify_text(text)
    policy = evaluate_policy(text, classification, policy_config)
    audit_preview = sanitize_text(text, policy_config, classification["issues"]) if classification["issues"] else policy["sanitized_text"]
    stored_sanitized = (
        audit_preview
        if policy_snapshot.audit_storage == "PROTECTED" and classification["issues"]
        else policy["sanitized_text"]
    )
    audit_original = protected_original_for_audit(
        original_text=text,
        sanitized_text=audit_preview,
        issues=classification["issues"],
        audit_storage=policy_snapshot.audit_storage,
    )

    incident = log_incident(
        db,
        source=req.source,
        user_id=req.user_id,
        original_text=audit_original,
        sanitized_text=stored_sanitized,
        risk_level=classification["risk_level"],
        issues=classification["issues"],
        decision=policy["decision"],
        policy_snapshot=policy_config,
    )

    return AnalyzeResponse(
        risk_level=classification["risk_level"],
        issues=classification["issues"],
        decision=policy["decision"],
        sanitized_text=policy["sanitized_text"],
        incident_id=incident.id,
    )


@app.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    source: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[IncidentOut]:
    stmt = select(Incident)
    if source:
        stmt = stmt.where(Incident.source == source)
    if risk_level:
        stmt = stmt.where(Incident.risk_level == risk_level)
    stmt = stmt.order_by(Incident.timestamp.desc(), Incident.id.desc())
    incidents = list(db.execute(stmt).scalars().all())
    return incidents


@app.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> IncidentOut:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
