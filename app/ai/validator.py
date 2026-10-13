
from dataclasses import dataclass, field

from app.ai.evidence_context import EvidenceContextValidator
from app.ai.models import (
    AIAnalysisResult,
    AIVulnerability,
    ExploitationStatus,
    PatchStatus,
    ZeroDayStatus,
)


@dataclass
class ValidationIssue:
    cve: str | None
    field: str
    message: str


@dataclass
class ValidationResult:
    accepted: list[AIVulnerability] = field(default_factory=list)
    rejected: list[AIVulnerability] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)


class AIResultValidator:
    EVIDENCE_FIELDS = (
        'vulnerability_type',
        'affected_versions',
        'cvss',
        'exploitation',
        'patch',
        'zero_day',
    )

    CONTEXT_FIELDS = (
        'exploitation',
        'zero_day',
    )

    def validate(
        self,
        result: AIAnalysisResult,
        article_text: str,
        extracted_cves: list[str],
    ) -> ValidationResult:
        validation = ValidationResult()
        normalized_text = self._normalize(article_text)

        known_cves = {
            cve.upper()
            for cve in extracted_cves
        }

        for original in result.vulnerabilities:
            vulnerability = original.model_copy(deep=True)
            issues: list[ValidationIssue] = []

            if (
                vulnerability.cve
                and vulnerability.cve.upper() not in known_cves
            ):
                validation.rejected.append(vulnerability)

                validation.issues.append(
                    ValidationIssue(
                        cve=vulnerability.cve,
                        field='cve',
                        message='CVE was not found by CVEExtractor',
                    )
                )
                continue

            for field_name in self.EVIDENCE_FIELDS:
                quote = getattr(
                    vulnerability.evidence,
                    field_name,
                )

                if not quote:
                    continue

                if self._normalize(quote) not in normalized_text:
                    setattr(
                        vulnerability.evidence,
                        field_name,
                        None,
                    )

                    issues.append(
                        ValidationIssue(
                            cve=vulnerability.cve,
                            field=f'evidence.{field_name}',
                            message='Evidence not found in article',
                        )
                    )
                    continue

                if (
                    field_name in self.CONTEXT_FIELDS
                    and vulnerability.cve
                ):
                    check = EvidenceContextValidator.check(
                        article_text=article_text,
                        cve=vulnerability.cve,
                        quote=quote,
                    )

                    if not check.valid:
                        setattr(
                            vulnerability.evidence,
                            field_name,
                            None,
                        )

                        issues.append(
                            ValidationIssue(
                                cve=vulnerability.cve,
                                field=f'evidence.{field_name}',
                                message=check.reason,
                            )
                        )

            if (
                vulnerability.vulnerability_type
                and not vulnerability.evidence.vulnerability_type
            ):
                vulnerability.vulnerability_type = None

            if (
                vulnerability.affected_versions
                and not vulnerability.evidence.affected_versions
            ):
                vulnerability.affected_versions = []

            if not vulnerability.evidence.cvss:
                if vulnerability.cvss_score is not None:
                    vulnerability.cvss_score = None

                    issues.append(
                        ValidationIssue(
                            cve=vulnerability.cve,
                            field='cvss',
                            message='Unverified CVSS cleared',
                        )
                    )

                vulnerability.severity = 'UNKNOWN'

            if not vulnerability.evidence.exploitation:
                vulnerability.exploitation_status = (
                    ExploitationStatus.UNKNOWN
                )

            if not vulnerability.evidence.patch:
                vulnerability.patch_status = (
                    PatchStatus.UNKNOWN
                )

            if not vulnerability.evidence.zero_day:
                if vulnerability.zero_day_status == ZeroDayStatus.POTENTIAL:
                    vulnerability.zero_day_status = ZeroDayStatus.NONE

                # This flag contributes to the 0-day score.
                # Do not trust it without supported context.
                vulnerability.previously_unknown = None

            validation.accepted.append(vulnerability)
            validation.issues.extend(issues)

        return validation

    @staticmethod
    def _normalize(text: str) -> str:
        return ' '.join(text.lower().split())