from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Notification(Base):
    __tablename__ = 'notifications'

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )

    vulnerability_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey('vulnerabilities.id', ondelete='CASCADE'),
        nullable=False,
    )

    publication_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey('publications.id', ondelete='CASCADE'),
        nullable=False,
    )

    channel: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default='TELEGRAM',
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default='PENDING',
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            'vulnerability_id',
            'channel',
            name='uq_notifications_vulnerability_channel',
        ),
    )