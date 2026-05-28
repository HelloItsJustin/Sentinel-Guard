from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Incident

PROTECTED_STORAGE_NOTE = "[PROTECTED ORIGINAL STORED AS SANITIZED PREVIEW]"


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _incident_payload_for_hash(
    *,
    timestamp: datetime,
    source: str,
    user_id: str,
    original_text: str,
    sanitized_text: str | None,
    risk_level: str,
    issues: list[str],
    decision: str,
    policy_snapshot: dict[str, object] | None,
) -> str:
    payload = {
        "timestamp": timestamp.isoformat(),
        "source": source,
        "user_id": user_id,
        "original_text": original_text,
        "sanitized_text": sanitized_text,
        "risk_level": risk_level,
        "issues": issues,
        "decision": decision,
        "policy_snapshot": policy_snapshot,
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _get_previous_hash(db: Session) -> str:
    stmt = select(Incident.hash_chain).order_by(Incident.id.desc()).limit(1)
    prev = db.execute(stmt).scalar_one_or_none()
    return prev or "GENESIS"


def protected_original_for_audit(
    *,
    original_text: str,
    sanitized_text: str | None,
    issues: list[str],
    audit_storage: str = "PROTECTED",
) -> str:
    if audit_storage == "FULL_TEXT" or not issues:
        return original_text

    preview = sanitized_text or ""
    if not preview.strip():
        preview = "[SENSITIVE CONTENT REDACTED]"
    return f"{PROTECTED_STORAGE_NOTE}\n{preview.strip()}"


def log_incident(
    db: Session,
    *,
    source: str,
    user_id: str,
    original_text: str,
    sanitized_text: str | None,
    risk_level: str,
    issues: list[str],
    decision: str,
    policy_snapshot: dict[str, object] | None = None,
) -> Incident:
    timestamp = datetime.now(timezone.utc)
    prev_hash = _get_previous_hash(db)
    policy_snapshot_json = json.dumps(policy_snapshot, sort_keys=True, ensure_ascii=False) if policy_snapshot else None
    payload = _incident_payload_for_hash(
        timestamp=timestamp,
        source=source,
        user_id=user_id,
        original_text=original_text,
        sanitized_text=sanitized_text,
        risk_level=risk_level,
        issues=issues,
        decision=decision,
        policy_snapshot=policy_snapshot,
    )
    hash_chain = _sha256_hex(prev_hash + payload)

    incident = Incident(
        timestamp=timestamp,
        source=source,
        user_id=user_id,
        original_text=original_text,
        sanitized_text=sanitized_text,
        risk_level=risk_level,
        issues=json.dumps(issues, ensure_ascii=False),
        decision=decision,
        policy_snapshot=policy_snapshot_json,
        hash_chain=hash_chain,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident
