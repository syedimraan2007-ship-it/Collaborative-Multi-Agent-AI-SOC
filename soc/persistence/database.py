"""
Database Engine Configuration and Session Factory.
Supports PostgreSQL (asyncpg/psycopg) with fallback to SQLite for local development.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from soc.persistence.models import Base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./soc_data.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)
