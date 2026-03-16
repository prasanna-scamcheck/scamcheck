from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, DateTime,
    ForeignKey, Table, Boolean, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import config

# ── Engine & Session ──
connect_args = {"check_same_thread": False} if "sqlite" in config.DATABASE_URL else {}
engine = create_engine(config.DATABASE_URL, connect_args=connect_args, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Association Table: Indicator Links ──
indicator_links = Table(
    "indicator_links", Base.metadata,
    Column("indicator_id", Integer, ForeignKey("indicators.id"), primary_key=True),
    Column("linked_indicator_id", Integer, ForeignKey("indicators.id"), primary_key=True),
)


class Indicator(Base):
    """Core intelligence record — a phone, UPI, email, domain, bank account, or wallet."""
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ref_id = Column(String(20), unique=True, nullable=False, index=True)  # IND-001
    type = Column(String(20), nullable=False, index=True)  # phone|upi|bank_account|email|domain|wallet
    value = Column(String(500), nullable=False, index=True)
    normalized_value = Column(String(500), nullable=False, index=True)  # stripped/lowered for search
    risk_score = Column(Float, default=0, index=True)
    complaint_count = Column(Integer, default=0)
    category = Column(String(100), nullable=True)
    location = Column(String(200), nullable=True)
    status = Column(String(20), default="unverified")  # unverified|active|confirmed|safe
    notes = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Many-to-many self-referential relationship
    linked_indicators = relationship(
        "Indicator",
        secondary=indicator_links,
        primaryjoin=id == indicator_links.c.indicator_id,
        secondaryjoin=id == indicator_links.c.linked_indicator_id,
        backref="linked_from",
        lazy="select"
    )

    reports = relationship("Report", back_populates="indicator_rel", lazy="select")

    __table_args__ = (
        Index("ix_indicators_search", "normalized_value", "type"),
    )

    def to_dict(self, include_linked=False):
        data = {
            "id": self.id,
            "ref_id": self.ref_id,
            "type": self.type,
            "value": self.value,
            "risk_score": self.risk_score,
            "complaint_count": self.complaint_count,
            "category": self.category,
            "location": self.location,
            "status": self.status,
            "notes": self.notes,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }
        if include_linked:
            data["linked_indicators"] = [
                {
                    "id": li.id,
                    "ref_id": li.ref_id,
                    "type": li.type,
                    "value": li.value,
                    "risk_score": li.risk_score,
                    "complaint_count": li.complaint_count,
                    "category": li.category,
                    "status": li.status,
                }
                for li in self.linked_indicators
            ]
        return data


class Report(Base):
    """User-submitted fraud report, enters moderation queue."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ref_id = Column(String(20), unique=True, nullable=False, index=True)  # RPT-001
    indicator_value = Column(String(500), nullable=False)
    indicator_type = Column(String(20), nullable=False)
    category = Column(String(100), nullable=True)
    description = Column(Text, nullable=False)
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    screenshot_path = Column(String(500), nullable=True)
    status = Column(String(20), default="pending", index=True)  # pending|approved|rejected
    indicator_id = Column(Integer, ForeignKey("indicators.id"), nullable=True)
    submitted_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime, nullable=True)
    reviewer_notes = Column(Text, nullable=True)

    indicator_rel = relationship("Indicator", back_populates="reports")

    def to_dict(self):
        return {
            "id": self.id,
            "ref_id": self.ref_id,
            "indicator_value": self.indicator_value,
            "indicator_type": self.indicator_type,
            "category": self.category,
            "description": self.description,
            "city": self.city,
            "state": self.state,
            "status": self.status,
            "indicator_id": self.indicator_id,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
        }


class AdminUser(Base):
    """Admin accounts for dashboard access."""
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    role = Column(String(20), default="moderator")  # moderator|admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def create_tables():
    Base.metadata.create_all(bind=engine)
