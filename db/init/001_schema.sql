-- ============================================================
-- VulnScout
-- Initial PostgreSQL schema
-- ============================================================


-- ============================================================
-- SOURCES
-- Источники публикаций: SecurityWeek, CISA, vendor advisory и т.д.
-- ============================================================

CREATE TABLE sources (
    id BIGSERIAL PRIMARY KEY,

    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(20) NOT NULL,
    url TEXT NOT NULL,

    trust_level SMALLINT NOT NULL DEFAULT 50,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Интервал проверки источника в секундах
    poll_interval INTEGER NOT NULL DEFAULT 300,

    last_checked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT sources_trust_level_check
        CHECK (trust_level BETWEEN 0 AND 100),

    CONSTRAINT sources_poll_interval_check
        CHECK (poll_interval > 0)
);


-- ============================================================
-- PRODUCTS
-- Продукты, которые отслеживает VulnScout
-- ============================================================

CREATE TABLE products (
    id BIGSERIAL PRIMARY KEY,

    vendor VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (vendor, name)
);


-- ============================================================
-- PRODUCT ALIASES
-- Альтернативные названия продукта.
--
-- Например:
-- VMware vCenter Server
--
-- aliases:
-- vCenter
-- vCenter Server
-- VMware vCenter
-- VCSA
-- ============================================================

CREATE TABLE product_aliases (
    id BIGSERIAL PRIMARY KEY,

    product_id BIGINT NOT NULL
        REFERENCES products(id)
        ON DELETE CASCADE,

    alias VARCHAR(255) NOT NULL,

    UNIQUE (product_id, alias)
);


-- ============================================================
-- PUBLICATIONS
-- Сырые публикации, полученные Collector'ами.
--
-- Publication != Vulnerability.
--
-- Несколько публикаций могут описывать одну уязвимость.
-- ============================================================

CREATE TABLE publications (
    id BIGSERIAL PRIMARY KEY,

    source_id BIGINT NOT NULL
        REFERENCES sources(id)
        ON DELETE RESTRICT,

    url TEXT NOT NULL,

    title TEXT NOT NULL,

    author TEXT,

    published_at TIMESTAMPTZ,

    -- Когда VulnScout получил публикацию
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Текст статьи / advisory
    raw_text TEXT,

    -- Исходные данные Collector'а
    raw_data JSONB,

    -- SHA-256 содержимого публикации
    content_hash VARCHAR(64),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (source_id, url)
);


-- ============================================================
-- VULNERABILITIES
-- Нормализованные события об уязвимостях.
--
-- CVE может отсутствовать:
-- новая / потенциальная 0-day уязвимость может появиться
-- до присвоения CVE.
-- ============================================================

CREATE TABLE vulnerabilities (
    id BIGSERIAL PRIMARY KEY,

    cve VARCHAR(32),

    vendor VARCHAR(255),

    product VARCHAR(255),

    title TEXT,

    description TEXT,

    -- Например:
    -- ["8.0 < 8.0.3", "7.x"]
    affected_versions JSONB,

    cvss_score NUMERIC(3,1),

    severity VARCHAR(20),

    -- UNKNOWN
    -- NONE
    -- SUSPECTED
    -- ACTIVE
    exploitation_status VARCHAR(20)
        NOT NULL
        DEFAULT 'UNKNOWN',

    -- UNKNOWN
    -- UNAVAILABLE
    -- AVAILABLE
    -- MITIGATION_ONLY
    patch_status VARCHAR(20)
        NOT NULL
        DEFAULT 'UNKNOWN',

    -- NONE
    -- SUSPICIOUS
    -- POTENTIAL
    -- CONFIRMED
    zero_day_status VARCHAR(20)
        NOT NULL
        DEFAULT 'NONE',

    zero_day_score INTEGER
        NOT NULL
        DEFAULT 0,

    -- Уверенность анализа:
    -- 0.000 - 1.000
    confidence NUMERIC(4,3),

    first_seen_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    last_seen_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    updated_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    CONSTRAINT vulnerabilities_cvss_score_check
        CHECK (
            cvss_score IS NULL
            OR cvss_score BETWEEN 0 AND 10
        ),

    CONSTRAINT vulnerabilities_confidence_check
        CHECK (
            confidence IS NULL
            OR confidence BETWEEN 0 AND 1
        ),

    CONSTRAINT vulnerabilities_exploitation_status_check
        CHECK (
            exploitation_status IN (
                'UNKNOWN',
                'NONE',
                'SUSPECTED',
                'ACTIVE'
            )
        ),

    CONSTRAINT vulnerabilities_patch_status_check
        CHECK (
            patch_status IN (
                'UNKNOWN',
                'UNAVAILABLE',
                'AVAILABLE',
                'MITIGATION_ONLY'
            )
        ),

    CONSTRAINT vulnerabilities_zero_day_status_check
        CHECK (
            zero_day_status IN (
                'NONE',
                'SUSPICIOUS',
                'POTENTIAL',
                'CONFIRMED'
            )
        )
);


-- ============================================================
-- VULNERABILITY <-> PUBLICATION
--
-- Связь many-to-many.
--
-- Одна уязвимость:
-- SecurityWeek ─┐
-- CISA ─────────┼──> Vulnerability
-- Vendor ───────┘
--
-- Одна публикация теоретически также может описывать
-- несколько уязвимостей.
-- ============================================================

CREATE TABLE vulnerability_publications (
    vulnerability_id BIGINT NOT NULL
        REFERENCES vulnerabilities(id)
        ON DELETE CASCADE,

    publication_id BIGINT NOT NULL
        REFERENCES publications(id)
        ON DELETE CASCADE,

    PRIMARY KEY (
        vulnerability_id,
        publication_id
    )
);


-- ============================================================
-- INDEXES
-- ============================================================

-- Поиск публикаций по дате
CREATE INDEX idx_publications_published_at
    ON publications (published_at);


-- Поиск / дедупликация по хэшу
CREATE INDEX idx_publications_content_hash
    ON publications (content_hash);


-- Поиск по CVE
CREATE INDEX idx_vulnerabilities_cve
    ON vulnerabilities (cve);


-- Выборка потенциальных zero-day
CREATE INDEX idx_vulnerabilities_zero_day_status
    ON vulnerabilities (zero_day_status);


-- Выборка активно эксплуатируемых уязвимостей
CREATE INDEX idx_vulnerabilities_exploitation_status
    ON vulnerabilities (exploitation_status);


-- Выборка по severity
CREATE INDEX idx_vulnerabilities_severity
    ON vulnerabilities (severity);


-- Алиасы продуктов понадобятся Pre-filter'у
CREATE INDEX idx_product_aliases_alias
    ON product_aliases (alias);


-- ============================================================
-- END
-- ============================================================