from app.ai.models import (
    AIVulnerability,
    ExploitationStatus,
    PatchStatus,
    ZeroDayStatus,
)
from app.services.zero_day_scorer import (
    ZeroDayScorer,
)


def main():
    scorer = ZeroDayScorer()

    vulnerability = AIVulnerability(
        cve='CVE-2026-88771',
        vendor='Citrix',
        product='NetScaler',
        title='CVE-2026-88771',
        vulnerability_type='Remote Code Execution',
        affected_versions=[],
        cvss_score=9.5,
        severity='Critical',
        exploitation_status=ExploitationStatus.ACTIVE,
        patch_status=PatchStatus.AVAILABLE,
        previously_unknown=None,
        zero_day_status=ZeroDayStatus.POTENTIAL,
        confidence=1.0,
    )

    result = scorer.score(
        vulnerability
    )

    print(f'Score: {result.score}')
    print(f'Status: {result.status.value}')
    print()

    print('Reasons:')

    for reason in result.reasons:
        print(
            f'  {reason.signal}: '
            f'+{reason.points}'
        )


if __name__ == '__main__':
    main()