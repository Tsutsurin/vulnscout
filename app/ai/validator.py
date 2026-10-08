from dataclasses import dataclass, field

from app.ai.models import (
    AIAnalysisResult,
    AIVulnerability,
)


@dataclass
class ValidationIssue:
    cve: str | None
    field: str
    message: str


@dataclass
class ValidationResult:
    accepted: list[AIVulnerability] = field(
        default_factory=list
    )
    rejected: list[AIVulnerability] = field(
        default_factory=list
    )
    issues: list[ValidationIssue] = field(
        default_factory=list
    )


class AIResultValidator:
    def validate(
        self,
        result: AIAnalysisResult,
        article_text: str,
        extracted_cves: list[str],
    ) -> ValidationResult:
        validation = ValidationResult()

        normalized_text = self._normalize(
            article_text
        )

        known_cves = {
            cve.upper()
            for cve in extracted_cves
        }

        for vulnerability in result.vulnerabilities:
            issues = []

            # CVE must have been found deterministically
            # by CVEExtractor.
            if (
                vulnerability.cve
                and vulnerability.cve.upper()
                not in known_cves
            ):
                issues.append(
                    ValidationIssue(
                        cve=vulnerability.cve,
                        field='cve',
                        message=(
                            'CVE was not found '
                            'by CVEExtractor'
                        ),
                    )
                )

            # Every evidence value returned by the LLM
            # must exist verbatim in the article.
            evidence_fields = {
                'vulnerability_type':
                    vulnerability.evidence.vulnerability_type,
                'affected_versions':
                    vulnerability.evidence.affected_versions,
                'cvss':
                    vulnerability.evidence.cvss,
                'exploitation':
                    vulnerability.evidence.exploitation,
                'patch':
                    vulnerability.evidence.patch,
                'zero_day':
                    vulnerability.evidence.zero_day,
            }

            for field_name, evidence in (
                evidence_fields.items()
            ):
                if not evidence:
                    continue

                if (
                    self._normalize(evidence)
                    not in normalized_text
                ):
                    issues.append(
                        ValidationIssue(
                            cve=vulnerability.cve,
                            field=f'evidence.{field_name}',
                            message=(
                                'Evidence was not found '
                                'in article text'
                            ),
                        )
                    )

            # Vulnerability type must have supporting
            # evidence when populated.
            if (
                vulnerability.vulnerability_type
                and not vulnerability.evidence.vulnerability_type
            ):
                issues.append(
                    ValidationIssue(
                        cve=vulnerability.cve,
                        field='vulnerability_type',
                        message=(
                            'Vulnerability type '
                            'has no evidence'
                        ),
                    )
                )

            # Affected versions must have supporting
            # evidence when populated.
            if (
                vulnerability.affected_versions
                and not vulnerability.evidence.affected_versions
            ):
                issues.append(
                    ValidationIssue(
                        cve=vulnerability.cve,
                        field='affected_versions',
                        message=(
                            'Affected versions '
                            'have no evidence'
                        ),
                    )
                )

            # CVSS score and severity must have
            # supporting evidence when populated.
            if (
                (
                    vulnerability.cvss_score is not None
                    or vulnerability.severity is not None
                )
                and not vulnerability.evidence.cvss
            ):
                issues.append(
                    ValidationIssue(
                        cve=vulnerability.cve,
                        field='cvss',
                        message=(
                            'CVSS or severity '
                            'has no evidence'
                        ),
                    )
                )

            if issues:
                validation.rejected.append(
                    vulnerability
                )

                validation.issues.extend(
                    issues
                )
            else:
                validation.accepted.append(
                    vulnerability
                )

        return validation

    @staticmethod
    def _normalize(
        text: str,
    ) -> str:
        return ' '.join(
            text.lower().split()
        )