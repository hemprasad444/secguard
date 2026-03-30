import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import Column, String, Boolean, Integer, Text, DateTime, ForeignKey, Numeric, Index, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.database import Base


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        # Prevent duplicate findings per project — only for non-null fingerprints
        Index(
            "uq_finding_project_fingerprint",
            "project_id", "fingerprint",
            unique=True,
            postgresql_where=text("fingerprint IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1), nullable=True)
    status: Mapped[str] = mapped_column(String, default="open", nullable=False)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    close_reason: Mapped[str | None] = mapped_column(String(50), nullable=True)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    scan = relationship("Scan", back_populates="findings", lazy="selectin")
    project = relationship("Project", back_populates="findings", lazy="selectin")
    assignee = relationship("User", foreign_keys=[assigned_to], lazy="selectin")
    closed_by_user = relationship("User", foreign_keys=[closed_by], lazy="selectin")
