
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    PrimaryKeyConstraint,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Source(Base):
    __tablename__ = 'sources'

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
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
        server_default='50',
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default='true',
    )

    poll_interval: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default='300',
    )

    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    publications: Mapped[list['Publication']] = relationship(
        'Publication',
        back_populates='source',
    )

    __table_args__ = (
        CheckConstraint(
            'trust_level BETWEEN 0 AND 100',
            name='sources_trust_level_check',
        ),
        CheckConstraint(
            'poll_interval > 0',
            name='sources_poll_interval_check',
        ),
    )


class Product(Base):
    __tablename__ = 'products'

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
        server_default='true',
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    aliases: Mapped[list['ProductAlias']] = relationship(
        'ProductAlias',
        back_populates='product',
        cascade='all, delete-orphan',
    )

    __table_args__ = (
        UniqueConstraint(
            'vendor',
            'name',
            name='products_vendor_name_key',
        ),
    )


class ProductAlias(Base):
    __tablename__ = 'product_aliases'

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
        'Product',
        back_populates='aliases',
    )

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


class Publication(Base):
    __tablename__ = 'publications'

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
        nullable=True,
    )

    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    raw_text: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    raw_data: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    content_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    source: Mapped['Source'] = relationship(
        'Source',
        back_populates='publications',
    )

    vulnerability_links: Mapped[
        list['VulnerabilityPublication']
    ] = relationship(
        'VulnerabilityPublication',
        back_populates='publication',
        cascade='all, delete-orphan',
    )

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


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )

    cve: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    vendor: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    product: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    title: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    affected_versions: Mapped[list | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    cvss_score: Mapped[float | None] = mapped_column(
        Numeric(3, 1),
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    exploitation_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default='UNKNOWN',
    )

    patch_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default='UNKNOWN',
    )

    zero_day_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default='NONE',
    )

    zero_day_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default='0',
    )

    confidence: Mapped[float | None] = mapped_column(
        Numeric(4, 3),
        nullable=True,
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

    publication_links: Mapped[
        list['VulnerabilityPublication']
    ] = relationship(
        'VulnerabilityPublication',
        back_populates='vulnerability',
        cascade='all, delete-orphan',
    )

    __table_args__ = (
        UniqueConstraint(
            'cve',
            name='uq_vulnerabilities_cve',
        ),
        Index(
            'idx_vulnerabilities_cve',
            'cve',
        ),
        Index(
            'idx_vulnerabilities_zero_day_status',
            'zero_day_status',
        ),
        Index(
            'idx_vulnerabilities_exploitation_status',
            'exploitation_status',
        ),
        Index(
            'idx_vulnerabilities_severity',
            'severity',
        ),
    )



class VulnerabilityPublication(Base):
    __tablename__ = 'vulnerability_publications'

    vulnerability_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            'vulnerabilities.id',
            ondelete='CASCADE',
        ),
        nullable=False,
    )

    publication_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            'publications.id',
            ondelete='CASCADE',
        ),
        nullable=False,
    )

    evidence: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    score_reasons: Mapped[list | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    analyzed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    vulnerability: Mapped['Vulnerability'] = relationship(
        'Vulnerability',
        back_populates='publication_links',
    )

    publication: Mapped['Publication'] = relationship(
        'Publication',
        back_populates='vulnerability_links',
    )

    __table_args__ = (
        PrimaryKeyConstraint(
            'vulnerability_id',
            'publication_id',
            name='vulnerability_publications_pkey',
        ),
    )