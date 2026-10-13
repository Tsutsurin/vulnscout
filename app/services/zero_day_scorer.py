import re
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
    MAX_SCORE = 19
    SUSPICIOUS_THRESHOLD = 5
    POTENTIAL_THRESHOLD = 8

    # Only explicit temporal/zero-day claims can promote a finding
    # to POTENTIAL. Other signals may raise suspicion but not confirm it.
    ZERO_DAY_EVIDENCE = re.compile(
        r'\bzero[ -]?days?\b|'
        r'\b(?:exploit(?:ed|ation|ing)?|attack(?:ed|s|ing)?)\b'
        r'.{0,100}\b(?:before|prior to)\b'
        r'.{0,70}\b(?:disclos(?:ure|ed)|patch|fix|release)\b',
        re.IGNORECASE | re.DOTALL,
    )
    NEGATED = re.compile(
        r'\b(?:not|no|never|without)\s+(?:an?\s+)?zero[ -]?day\b',
        re.IGNORECASE,
    )

    @classmethod
    def has_direct_evidence(cls, vulnerability: AIVulnerability) -> bool:
        quote = (vulnerability.evidence.zero_day or '').strip()
        return bool(
            quote
            and cls.ZERO_DAY_EVIDENCE.search(quote)
            and not cls.NEGATED.search(quote)
        )

    def score(self, vulnerability: AIVulnerability) -> ZeroDayScore:
        score = 0
        reasons: list[ScoreReason] = []
        direct = self.has_direct_evidence(vulnerability)

        if direct and vulnerability.zero_day_status == ZeroDayStatus.POTENTIAL:
            score += 5
            reasons.append(ScoreReason('explicit_zero_day', 5))

        if vulnerability.exploitation_status == ExploitationStatus.ACTIVE:
            score += 5
            reasons.append(ScoreReason('active_exploitation', 5))

        if vulnerability.previously_unknown is True:
            score += 4
            reasons.append(ScoreReason('previously_unknown', 4))

        if vulnerability.patch_status == PatchStatus.UNAVAILABLE:
            score += 3
            reasons.append(ScoreReason('patch_unavailable', 3))

        if vulnerability.cve is None:
            score += 2
            reasons.append(ScoreReason('cve_missing', 2))

        if direct and vulnerability.zero_day_status == ZeroDayStatus.POTENTIAL:
            # The score reflects prioritization, not proof of zero-day.
            status = ZeroDayStatus.POTENTIAL
        elif (
            vulnerability.zero_day_status == ZeroDayStatus.SUSPICIOUS
            or score >= self.SUSPICIOUS_THRESHOLD
        ):
            status = ZeroDayStatus.SUSPICIOUS
        else:
            status = ZeroDayStatus.NONE

        return ZeroDayScore(score=score, status=status, reasons=reasons)
