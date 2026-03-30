import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ControlFix(Base):
    __tablename__ = "control_fixes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    control_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    scanner: Mapped[str] = mapped_column(String(50), nullable=False)  # trivy, kubescape
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_type: Mapped[str] = mapped_column(String(50), default="strategic_merge", nullable=False)
    applicable_kinds: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    patch_template: Mapped[str] = mapped_column(Text, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="low", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
