from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


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

    affected_versions: list[str] = Field(default_factory=list)

    cvss_score: float | None = Field(default=None, ge=0, le=10)
    severity: str | None = None

    exploitation_status: ExploitationStatus = ExploitationStatus.UNKNOWN
    patch_status: PatchStatus = PatchStatus.UNKNOWN
    previously_unknown: bool | None = None
    zero_day_status: ZeroDayStatus = ZeroDayStatus.NONE
    evidence: Evidence = Field(default_factory=Evidence)
    confidence: float = Field(ge=0, le=1)

    @model_validator(mode='after')
    def normalize(self) -> 'AIVulnerability':
        self.vendor = ' '.join(self.vendor.split())
        self.product = ' '.join(self.product.split())

        if self.vendor and self.product.lower().startswith(
            self.vendor.lower() + ' '
        ):
            self.product = self.product[len(self.vendor):].strip()

        severity = (self.severity or '').strip().upper()
        if severity in {'', 'UNKNOWN', 'N/A', 'NONE'} and self.cvss_score is not None:
            # CVSS v3 severity bands; CVSS v4 requires its own severity rules.
            # In either case, a 9.5 score is Critical.
            score = self.cvss_score
            if score >= 9:
                severity = 'CRITICAL'
            elif score >= 7:
                severity = 'HIGH'
            elif score >= 4:
                severity = 'MEDIUM'
            elif score > 0:
                severity = 'LOW'
            else:
                severity = 'NONE'

        self.severity = severity or 'UNKNOWN'
        return self


class AIAnalysisResult(BaseModel):
    vulnerabilities: list[AIVulnerability] = Field(default_factory=list)
