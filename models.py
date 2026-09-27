from datetime import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base

class Scan(Base):
    __tablename__="scans"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )
    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    status: Mapped[str] = mapped_column(
        nullable=False
    )
    security_score: Mapped[int] = mapped_column(
        Integer,
        nullable=True
    )
    created_dtm: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.now(),
        nullable=False
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan"
    )

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )
    finding_code: Mapped[str] = mapped_column(
        String(150),
        nullable=True
    )
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )
    description: Mapped[str] = mapped_column(
        String(1000),
        nullable=False
    )
    recommendation: Mapped[str] = mapped_column(
        String(1000),
        nullable=False
    )
    evidence: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True
    )
    scan: Mapped["Scan"] = relationship(
        back_populates="findings"
    )