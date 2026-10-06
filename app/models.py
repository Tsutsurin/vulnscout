from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database import Base


class Source(Base):
    __tablename__ = 'sources'

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    trust_level: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        default=50,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    poll_interval: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=300,
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    publications: Mapped[list['Publication']] = relationship(
        back_populates='source',
    )


class Product(Base):
    __tablename__ = 'products'

    __table_args__ = (
        UniqueConstraint(
            'vendor',
            'name',
            name='products_vendor_name_key',
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )
    vendor: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    aliases: Mapped[list['ProductAlias']] = relationship(
        back_populates='product',
        cascade='all, delete-orphan',
    )


class ProductAlias(Base):
    __tablename__ = 'product_aliases'

    __table_args__ = (
        UniqueConstraint(
            'product_id',
            'alias',
            name='product_aliases_product_id_alias_key',
        ),
        Index(
            'idx_product_aliases_alias',
            'alias',
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )
    product_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            'products.id',
            ondelete='CASCADE',
        ),
        nullable=False,
    )
    alias: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    product: Mapped['Product'] = relationship(
        back_populates='aliases',
    )


class Publication(Base):
    __tablename__ = 'publications'

    __table_args__ = (
        UniqueConstraint(
            'source_id',
            'url',
            name='publications_source_id_url_key',
        ),
        Index(
            'idx_publications_content_hash',
            'content_hash',
        ),
        Index(
            'idx_publications_published_at',
            'published_at',
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )
    source_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            'sources.id',
            ondelete='RESTRICT',
        ),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    author: Mapped[str | None] = mapped_column(
        Text,
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    raw_text: Mapped[str | None] = mapped_column(
        Text,
    )
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
    )
    content_hash: Mapped[str | None] = mapped_column(
        String(64),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    source: Mapped['Source'] = relationship(
        back_populates='publications',
    )

    vulnerabilities: Mapped[list['Vulnerability']] = relationship(
        secondary='vulnerability_publications',
        back_populates='publications',
    )


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'

    __table_args__ = (
        Index(
            'idx_vulnerabilities_cve',
            'cve',
        ),
        Index(
            'idx_vulnerabilities_exploitation_status',
            'exploitation_status',
        ),
        Index(
            'idx_vulnerabilities_severity',
            'severity',
        ),
        Index(
            'idx_vulnerabilities_zero_day_status',
            'zero_day_status',
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )
    cve: Mapped[str | None] = mapped_column(
        String(32),
    )
    vendor: Mapped[str | None] = mapped_column(
        String(255),
    )
    product: Mapped[str | None] = mapped_column(
        String(255),
    )
    title: Mapped[str | None] = mapped_column(
        Text,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
    )
    affected_versions: Mapped[Any | None] = mapped_column(
        JSONB,
    )
    cvss_score: Mapped[Decimal | None] = mapped_column(
        Numeric(3, 1),
    )
    severity: Mapped[str | None] = mapped_column(
        String(20),
    )
    exploitation_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default='UNKNOWN',
    )
    patch_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default='UNKNOWN',
    )
    zero_day_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default='NONE',
    )
    zero_day_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    confidence: Mapped[Decimal | None] = mapped_column(
        Numeric(4, 3),
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    publications: Mapped[list['Publication']] = relationship(
        secondary='vulnerability_publications',
        back_populates='vulnerabilities',
    )


class VulnerabilityPublication(Base):
    __tablename__ = 'vulnerability_publications'

    vulnerability_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            'vulnerabilities.id',
            ondelete='CASCADE',
        ),
        primary_key=True,
    )
    publication_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            'publications.id',
            ondelete='CASCADE',
        ),
        primary_key=True,
    )