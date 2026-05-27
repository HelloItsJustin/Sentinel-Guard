from __future__ import annotations

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool


def _sqlite_url() -> str:
    db_path = os.getenv("SENTINELGUARD_DB_PATH", "sentinelguard.db")
    return f"sqlite:///{db_path}"


SQLALCHEMY_DATABASE_URL = _sqlite_url()

engine_kwargs = {"connect_args": {"check_same_thread": False}}
if SQLALCHEMY_DATABASE_URL == "sqlite:///:memory:":
    engine_kwargs["poolclass"] = StaticPool

engine = create_engine(SQLALCHEMY_DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
