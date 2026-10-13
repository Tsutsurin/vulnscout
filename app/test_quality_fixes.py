from app.ai.models import AIVulnerability, ZeroDayStatus
from app.models import Publication, Vulnerability
from app.services.notification import NotificationService
from app.services.zero_day_scorer import ZeroDayScorer


def sample(**overrides) -> AIVulnerability:
    values = {
        'cve': 'CVE-2026-88771',
        'vendor': 'Citrix',
        'product': 'Citrix NetScaler',
        'title': 'NetScaler vulnerability',
        'cvss_score': 9.5,
        'severity': 'UNKNOWN',
        'exploitation_status': 'ACTIVE',
        'patch_status': 'AVAILABLE',
        'zero_day_status': 'POTENTIAL',
        'confidence': 0.9,
    }

    values.update(overrides)

    return AIVulnerability.model_validate(values)


def test_without_explicit_zero_day_evidence() -> None:
    vulnerability = sample()

    assert vulnerability.product == 'NetScaler'
    assert vulnerability.severity == 'CRITICAL'

    result = ZeroDayScorer().score(vulnerability)

    assert result.status != ZeroDayStatus.POTENTIAL


def test_explicit_zero_day_evidence() -> None:
    vulnerability = sample(
        evidence={
            'zero_day': (
                'exploited in the wild as zero-days '
                'prior to vendor disclosure'
            )
        }
    )

    result = ZeroDayScorer().score(vulnerability)

    assert result.status == ZeroDayStatus.POTENTIAL


def test_message_without_zero_day_warning() -> None:
    vulnerability = Vulnerability(
        cve='CVE-2026-107406',
        vendor='Citrix',
        product='Citrix NetScaler',
        cvss_score=9.5,
        severity='UNKNOWN',
        zero_day_status='NONE',
        zero_day_score=0,
        exploitation_status='UNKNOWN',
        patch_status='AVAILABLE',
    )

    publication = Publication(
        url='https://example.com/advisory',
    )

    message = NotificationService.build_message(
        vulnerability,
        publication,
    )

    assert 'Citrix Citrix NetScaler' not in message
    assert 'Citrix NetScaler' in message
    assert 'CRITICAL' in message
    assert 'подтверждения аналитиком' not in message


def main() -> None:
    test_without_explicit_zero_day_evidence()
    test_explicit_zero_day_evidence()
    test_message_without_zero_day_warning()

    print('All quality checks passed')


if __name__ == '__main__':
    main()