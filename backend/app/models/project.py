import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, Integer, Text, DateTime, ForeignKey, Numeric
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.database import Base


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    repo_url: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    kubeconfig_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )

    organization = relationship("Organization", back_populates="projects")
    creator = relationship("User", foreign_keys=[created_by], lazy="selectin")
    scans = relationship("Scan", back_populates="project", lazy="selectin")
    findings = relationship("Finding", back_populates="project", lazy="selectin")
    reports = relationship("Report", back_populates="project", lazy="selectin")
