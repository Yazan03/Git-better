from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, create_engine, text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    source = Column(String(32), nullable=False)  # "json" | "scan" | "rescan"
    uploaded_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    total = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    by_language = Column(Text, default="{}")  # JSON-encoded
    parent_id = Column(Integer, ForeignKey("reports.id"), nullable=True, index=True)
    zip_filename = Column(String(255), nullable=True)
    repo_url = Column(String(512), nullable=True)
    repo_ref = Column(String(255), nullable=True)

    findings = relationship(
        "Finding", back_populates="report", cascade="all, delete-orphan"
    )
    parent = relationship("Report", remote_side=[id], backref="rescans")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False, index=True)
    file = Column(String(512), nullable=False)
    line = Column(Integer, nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    rule_id = Column(String(32), nullable=False, index=True)
    language = Column(String(32), nullable=False, index=True)
    message = Column(Text, nullable=False)
    code_snippet = Column(Text, default="")
    confidence = Column(String(16), default="LOW")
    ai_explanation = Column(Text, default="")

    report = relationship("Report", back_populates="findings")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), nullable=False, default="member")  # "admin" | "member"
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


def _migrate(engine):
    """Idempotent column adds for SQLite — no Alembic dependency."""
    with engine.begin() as conn:
        # reports table
        report_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(reports)"))}
        if "parent_id" not in report_cols:
            conn.execute(text("ALTER TABLE reports ADD COLUMN parent_id INTEGER"))
        if "zip_filename" not in report_cols:
            conn.execute(text("ALTER TABLE reports ADD COLUMN zip_filename VARCHAR(255)"))
        if "repo_url" not in report_cols:
            conn.execute(text("ALTER TABLE reports ADD COLUMN repo_url VARCHAR(512)"))
        if "repo_ref" not in report_cols:
            conn.execute(text("ALTER TABLE reports ADD COLUMN repo_ref VARCHAR(255)"))
        # findings table
        finding_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(findings)"))}
        if "confidence" not in finding_cols:
            conn.execute(text("ALTER TABLE findings ADD COLUMN confidence VARCHAR(16) DEFAULT 'LOW'"))
        if "ai_explanation" not in finding_cols:
            conn.execute(text("ALTER TABLE findings ADD COLUMN ai_explanation TEXT DEFAULT ''"))


def make_session(db_path: str):
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    Base.metadata.create_all(engine)
    _migrate(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
