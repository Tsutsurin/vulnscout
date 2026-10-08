from app.ai.models import AIAnalysisResult
from app.ai.validator import AIResultValidator


ARTICLE_TEXT = """
Both of these RCE vulnerabilities carry a critical
CVSSv4 score of 9.5, and both have been confirmed as
being actively exploited in the wild as zero-days
prior to the vendor disclosure.

The following vendor-supplied updates are available
to remediate the vulnerabilities.
"""


AI_RESPONSE = {
    'vulnerabilities': [
        {
            'cve': 'CVE-2026-88771',
            'vendor': 'Citrix',
            'product': 'NetScaler',
            'title': 'Remote code execution',
            'vulnerability_type': 'RCE',
            'cvss_score': 9.5,
            'exploitation_status': 'ACTIVE',
            'patch_status': 'AVAILABLE',
            'previously_unknown': True,
            'zero_day_status': 'POTENTIAL',
            'evidence': {
                'exploitation': (
                    'confirmed as being actively '
                    'exploited in the wild'
                ),
                'patch': (
                    'vendor-supplied updates are '
                    'available'
                ),
                'zero_day': (
                    'actively exploited in the wild '
                    'as zero-days prior to the '
                    'vendor disclosure'
                ),
            },
            'confidence': 0.95,
        },
        {
            'cve': 'CVE-2026-12345',
            'vendor': 'Citrix',
            'product': 'NetScaler',
            'title': 'Made up vulnerability',
            'exploitation_status': 'ACTIVE',
            'patch_status': 'UNAVAILABLE',
            'zero_day_status': 'POTENTIAL',
            'evidence': {
                'exploitation': (
                    'Hackers are exploiting this '
                    'everywhere'
                ),
            },
            'confidence': 0.99,
        },
    ]
}


def main():
    result = AIAnalysisResult.model_validate(
        AI_RESPONSE
    )

    validator = AIResultValidator()

    validation = validator.validate(
        result=result,
        article_text=ARTICLE_TEXT,
        extracted_cves=[
            'CVE-2026-88771',
            'CVE-2026-88772',
            'CVE-2026-88779',
        ],
    )

    print(
        f'Accepted: '
        f'{len(validation.accepted)}'
    )

    for vulnerability in validation.accepted:
        print(
            f'  {vulnerability.cve}'
        )

    print()
    print(
        f'Rejected: '
        f'{len(validation.rejected)}'
    )

    for vulnerability in validation.rejected:
        print(
            f'  {vulnerability.cve}'
        )

    print()
    print('Issues:')

    for issue in validation.issues:
        print(
            f'  {issue.cve} | '
            f'{issue.field} | '
            f'{issue.message}'
        )


if __name__ == '__main__':
    main()