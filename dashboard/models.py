from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    source = Column(String(32), nullable=False)  # "json" | "scan"
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    total = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    by_language = Column(Text, default="{}")  # JSON-encoded

    findings = relationship(
        "Finding", back_populates="report", cascade="all, delete-orphan"
    )


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

    report = relationship("Report", back_populates="findings")


def make_session(db_path: str):
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
