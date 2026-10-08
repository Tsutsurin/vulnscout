from dataclasses import dataclass

from app.ai.models import (
    AIVulnerability,
    ExploitationStatus,
    PatchStatus,
    ZeroDayStatus,
)


@dataclass
class ScoreReason:
    signal: str
    points: int


@dataclass
class ZeroDayScore:
    score: int
    status: ZeroDayStatus
    reasons: list[ScoreReason]


class ZeroDayScorer:
    SUSPICIOUS_THRESHOLD = 5
    POTENTIAL_THRESHOLD = 8

    def score(
        self,
        vulnerability: AIVulnerability,
    ) -> ZeroDayScore:
        score = 0
        reasons = []

        if (
            vulnerability.zero_day_status
            == ZeroDayStatus.POTENTIAL
        ):
            score += 5
            reasons.append(
                ScoreReason(
                    signal='explicit_zero_day',
                    points=5,
                )
            )

        if (
            vulnerability.exploitation_status
            == ExploitationStatus.ACTIVE
        ):
            score += 5
            reasons.append(
                ScoreReason(
                    signal='active_exploitation',
                    points=5,
                )
            )

        if vulnerability.previously_unknown is True:
            score += 4
            reasons.append(
                ScoreReason(
                    signal='previously_unknown',
                    points=4,
                )
            )

        if (
            vulnerability.patch_status
            == PatchStatus.UNAVAILABLE
        ):
            score += 3
            reasons.append(
                ScoreReason(
                    signal='patch_unavailable',
                    points=3,
                )
            )

        if vulnerability.cve is None:
            score += 2
            reasons.append(
                ScoreReason(
                    signal='cve_missing',
                    points=2,
                )
            )

        status = self._status_from_score(
            score
        )

        return ZeroDayScore(
            score=score,
            status=status,
            reasons=reasons,
        )

    def _status_from_score(
        self,
        score: int,
    ) -> ZeroDayStatus:
        if score >= self.POTENTIAL_THRESHOLD:
            return ZeroDayStatus.POTENTIAL

        if score >= self.SUSPICIOUS_THRESHOLD:
            return ZeroDayStatus.SUSPICIOUS

        return ZeroDayStatus.NONE