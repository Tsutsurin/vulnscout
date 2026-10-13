from dataclasses import dataclass, field

from app.ai.models import (
    AIAnalysisResult,
    AIVulnerability,
    ExploitationStatus,
    PatchStatus,
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
    def validate(
        self,
        result: AIAnalysisResult,
        article_text: str,
        extracted_cves: list[str],
    ) -> ValidationResult:
        validation = ValidationResult()
        normalized_text = self._normalize(article_text)
        known_cves = {cve.upper() for cve in extracted_cves}

        for vulnerability in result.vulnerabilities:
            issues: list[ValidationIssue] = []

            if (
                vulnerability.cve
                and vulnerability.cve.upper() not in known_cves
            ):
                issues.append(ValidationIssue(
                    cve=vulnerability.cve,
                    field='cve',
                    message='CVE was not found by CVEExtractor',
                ))

            evidence_fields = {
                'vulnerability_type': vulnerability.evidence.vulnerability_type,
                'affected_versions': vulnerability.evidence.affected_versions,
                'cvss': vulnerability.evidence.cvss,
                'exploitation': vulnerability.evidence.exploitation,
                'patch': vulnerability.evidence.patch,
                'zero_day': vulnerability.evidence.zero_day,
            }

            for field_name, evidence in evidence_fields.items():
                if evidence and self._normalize(evidence) not in normalized_text:
                    issues.append(ValidationIssue(
                        cve=vulnerability.cve,
                        field=f'evidence.{field_name}',
                        message='Evidence was not found in article text',
                    ))

            if (
                vulnerability.vulnerability_type
                and not vulnerability.evidence.vulnerability_type
            ):
                issues.append(ValidationIssue(
                    cve=vulnerability.cve,
                    field='vulnerability_type',
                    message='Vulnerability type has no evidence',
                ))

            if (
                vulnerability.affected_versions
                and not vulnerability.evidence.affected_versions
            ):
                issues.append(ValidationIssue(
                    cve=vulnerability.cve,
                    field='affected_versions',
                    message='Affected versions have no evidence',
                ))

            if (
                (vulnerability.cvss_score is not None
                 or vulnerability.severity not in {None, 'UNKNOWN'})
                and not vulnerability.evidence.cvss
            ):
                issues.append(ValidationIssue(
                    cve=vulnerability.cve,
                    field='cvss',
                    message='CVSS has no evidence',
                ))

            # A status without a supporting article quote is not a fact.
            # Downgrade to UNKNOWN rather than discarding a valid CVE.
            if (
                vulnerability.exploitation_status != ExploitationStatus.UNKNOWN
                and not vulnerability.evidence.exploitation
            ):
                vulnerability.exploitation_status = ExploitationStatus.UNKNOWN

            if (
                vulnerability.patch_status != PatchStatus.UNKNOWN
                and not vulnerability.evidence.patch
            ):
                vulnerability.patch_status = PatchStatus.UNKNOWN

            if issues:
                validation.rejected.append(vulnerability)
                validation.issues.extend(issues)
            else:
                validation.accepted.append(vulnerability)

        return validation

    @staticmethod
    def _normalize(text: str) -> str:
        return ' '.join(text.lower().split())
