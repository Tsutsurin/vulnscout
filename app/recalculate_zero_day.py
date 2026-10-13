
"""Recalculate aggregate zero-day ratings from stored publication evidence.

Dry-run by default. No AI calls and no notifications are generated.
"""

import argparse
import logging
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import select

from app.database import SessionLocal
from app.models import Vulnerability, VulnerabilityPublication
from app.services.zero_day_scorer import ZeroDayScorer

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Rating:
    score: int
    status: str


@dataclass(frozen=True)
class Change:
    cve: str
    old: Rating
    new: Rating


def _rating_for_link(link: VulnerabilityPublication) -> Rating:
    """Rebuild a publication score from persisted reason signals.

    Old explicit_zero_day reasons are ignored unless the persisted
    verbatim quote independently passes the current evidence check.
    """
    evidence = link.evidence if isinstance(link.evidence, dict) else {}
    quote = evidence.get('zero_day')

    direct = bool(
        isinstance(quote, str)
        and quote.strip()
        and ZeroDayScorer.ZERO_DAY_EVIDENCE.search(quote)
        and not ZeroDayScorer.NEGATED.search(quote)
    )

    allowed = {
        'active_exploitation': 5,
        'previously_unknown': 4,
        'patch_unavailable': 3,
        'cve_missing': 2,
    }

    signals = set()

    for reason in link.score_reasons or []:
        if isinstance(reason, dict):
            signal = reason.get('signal')
            if isinstance(signal, str):
                signals.add(signal)

    score = sum(
        points
        for signal, points in allowed.items()
        if signal in signals
    )

    if direct and 'explicit_zero_day' in signals:
        score += 5
        status = 'POTENTIAL'
    elif score >= ZeroDayScorer.SUSPICIOUS_THRESHOLD:
        status = 'SUSPICIOUS'
    else:
        status = 'NONE'

    return Rating(score=score, status=status)


def _aggregate(
    links: Sequence[VulnerabilityPublication],
) -> Rating | None:
    if not links:
        return None

    ratings = [_rating_for_link(link) for link in links]

    priority = {
        'NONE': 0,
        'SUSPICIOUS': 1,
        'POTENTIAL': 2,
    }

    return Rating(
        score=max(rating.score for rating in ratings),
        status=max(
            ratings,
            key=lambda rating: priority[rating.status],
        ).status,
    )


def recalculate(
    *,
    apply: bool,
    cve: str | None = None,
) -> tuple[int, int]:
    inspected = 0
    changed = 0

    with SessionLocal.begin() as session:
        query = select(Vulnerability).order_by(Vulnerability.id)

        if cve:
            query = query.where(
                Vulnerability.cve == cve.strip().upper()
            )

        if apply:
            query = query.with_for_update()

        vulnerabilities = session.scalars(query).all()

        for vulnerability in vulnerabilities:
            links = session.scalars(
                select(VulnerabilityPublication).where(
                    VulnerabilityPublication.vulnerability_id
                    == vulnerability.id
                )
            ).all()

            new = _aggregate(links)

            if new is None:
                logger.warning(
                    'Skipping %s: no publication evidence',
                    vulnerability.cve,
                )
                continue

            inspected += 1

            old = Rating(
                score=vulnerability.zero_day_score or 0,
                status=vulnerability.zero_day_status or 'NONE',
            )

            if old == new:
                continue

            changed += 1

            identifier = (
                vulnerability.cve
                or f'NO-CVE:{vulnerability.id}'
            )

            print(
                f'{identifier}: '
                f'{old.status}/{old.score} -> '
                f'{new.status}/{new.score}'
            )

            if apply:
                vulnerability.zero_day_score = new.score
                vulnerability.zero_day_status = new.status

    return inspected, changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        '--cve',
        help='Only inspect this CVE',
    )

    parser.add_argument(
        '--apply',
        action='store_true',
        help='Write changes to PostgreSQL (default: dry-run)',
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    inspected, changed = recalculate(
        apply=args.apply,
        cve=args.cve,
    )

    print(
        f'Inspected: {inspected}; '
        f'changes: {changed}; '
        f'mode: {"APPLY" if args.apply else "DRY-RUN"}'
    )


if __name__ == '__main__':
    main()