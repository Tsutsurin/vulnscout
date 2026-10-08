from pydantic import ValidationError

from app.ai.models import AIAnalysisResult


VALID_RESPONSE = {
    'vulnerabilities': [
        {
            'cve': 'CVE-2026-88771',
            'vendor': 'Citrix',
            'product': 'NetScaler',
            'title': (
                'Remote code execution vulnerability '
                'in Citrix NetScaler'
            ),
            'vulnerability_type': 'RCE',
            'affected_versions': [
                'NetScaler ADC 14.1',
                'NetScaler Gateway 14.1',
            ],
            'cvss_score': 9.5,
            'severity': 'CRITICAL',
            'exploitation_status': 'ACTIVE',
            'patch_status': 'AVAILABLE',
            'previously_unknown': True,
            'zero_day_status': 'POTENTIAL',
            'evidence': {
                'exploitation': (
                    'Both have been confirmed as being '
                    'actively exploited in the wild'
                ),
                'patch': (
                    'vendor-supplied updates are available'
                ),
                'zero_day': (
                    'actively exploited in the wild as '
                    'zero-days prior to the vendor disclosure'
                ),
            },
            'confidence': 0.95,
        }
    ]
}


INVALID_RESPONSE = {
    'vulnerabilities': [
        {
            'cve': 'CVE-2026-12345',
            'vendor': 'Citrix',
            'product': 'NetScaler',
            'title': 'Test',
            'cvss_score': 15.0,
            'exploitation_status': 'HACKED',
            'patch_status': 'AVAILABLE',
            'zero_day_status': 'CONFIRMED',
            'confidence': 2.0,
        }
    ]
}


def main():
    print('Testing valid response...')

    result = AIAnalysisResult.model_validate(
        VALID_RESPONSE
    )

    print('VALID OK')
    print(
        result.model_dump_json(
            indent=2
        )
    )

    print()
    print('Testing invalid response...')

    try:
        AIAnalysisResult.model_validate(
            INVALID_RESPONSE
        )
    except ValidationError as error:
        print('INVALID REJECTED')
        print(error)


if __name__ == '__main__':
    main()