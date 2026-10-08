from enum import StrEnum

from pydantic import BaseModel, Field


class ExploitationStatus(StrEnum):
    UNKNOWN = 'UNKNOWN'
    NONE = 'NONE'
    SUSPECTED = 'SUSPECTED'
    ACTIVE = 'ACTIVE'


class PatchStatus(StrEnum):
    UNKNOWN = 'UNKNOWN'
    UNAVAILABLE = 'UNAVAILABLE'
    AVAILABLE = 'AVAILABLE'
    MITIGATION_ONLY = 'MITIGATION_ONLY'


class ZeroDayStatus(StrEnum):
    NONE = 'NONE'
    SUSPICIOUS = 'SUSPICIOUS'
    POTENTIAL = 'POTENTIAL'


class Evidence(BaseModel):
    vulnerability_type: str | None = None
    affected_versions: str | None = None
    cvss: str | None = None
    exploitation: str | None = None
    patch: str | None = None
    zero_day: str | None = None


class AIVulnerability(BaseModel):
    cve: str | None = None

    vendor: str
    product: str

    title: str
    vulnerability_type: str | None = None

    affected_versions: list[str] = Field(
        default_factory=list
    )

    cvss_score: float | None = Field(
        default=None,
        ge=0,
        le=10,
    )

    severity: str | None = None

    exploitation_status: ExploitationStatus = (
        ExploitationStatus.UNKNOWN
    )

    patch_status: PatchStatus = (
        PatchStatus.UNKNOWN
    )

    previously_unknown: bool | None = None

    zero_day_status: ZeroDayStatus = (
        ZeroDayStatus.NONE
    )

    evidence: Evidence = Field(
        default_factory=Evidence
    )

    confidence: float = Field(
        ge=0,
        le=1,
    )


class AIAnalysisResult(BaseModel):
    vulnerabilities: list[AIVulnerability] = Field(
        default_factory=list
    )