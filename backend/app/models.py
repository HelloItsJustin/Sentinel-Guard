from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    source: Mapped[str] = mapped_column(String(32), index=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)

    original_text: Mapped[str] = mapped_column(Text)
    sanitized_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    issues: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(String(16), index=True)
    policy_snapshot: Mapped[str | None] = mapped_column(Text, nullable=True)

    hash_chain: Mapped[str] = mapped_column(String(64), index=True)
