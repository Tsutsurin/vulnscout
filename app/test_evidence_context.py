
from app.ai.evidence_context import EvidenceContextValidator


def check(
    article: str,
    cve: str,
    quote: str,
    expected: bool,
) -> None:
    result = EvidenceContextValidator.check(
        article_text=article,
        cve=cve,
        quote=quote,
    )

    assert result.valid is expected, (
        f'CVE={cve}, '
        f'expected={expected}, '
        f'actual={result.valid}, '
        f'reason={result.reason}'
    )


def test_direct_evidence():
    article = (
        'CVE-2026-88779 was exploited in-the-wild '
        'as a zero-day prior to disclosure.'
    )

    quote = 'exploited in-the-wild as a zero-day'

    check(article, 'CVE-2026-88779', quote, True)
    check(article, 'CVE-2026-88771', quote, False)


def test_both_same_sentence():
    article = (
        'CVE-2026-88771 and CVE-2026-88772 '
        'were both exploited as zero-days.'
    )

    quote = 'both exploited as zero-days'

    check(article, 'CVE-2026-88771', quote, True)
    check(article, 'CVE-2026-88772', quote, True)
    check(article, 'CVE-2026-88779', quote, False)


def test_both_next_sentence():
    article = (
        'CVE-2026-88771 and CVE-2026-88772 '
        'affect Citrix NetScaler. '
        'Both were exploited as zero-days.'
    )

    quote = 'Both were exploited as zero-days'

    check(article, 'CVE-2026-88771', quote, True)
    check(article, 'CVE-2026-88772', quote, True)


def test_singular_reference():
    article = (
        'Citrix disclosed CVE-2026-88779. '
        'This new vulnerability was disclosed as being '
        'exploited in-the-wild as a zero-day prior to disclosure.'
    )

    quote = (
        'This new vulnerability was disclosed as being '
        'exploited in-the-wild as a zero-day prior to disclosure'
    )

    check(article, 'CVE-2026-88779', quote, True)
    check(article, 'CVE-2026-88771', quote, False)


def test_singular_ambiguous():
    article = (
        'CVE-2026-88771 and CVE-2026-88772 '
        'affect Citrix NetScaler. '
        'This vulnerability was exploited as a zero-day.'
    )

    quote = 'This vulnerability was exploited as a zero-day'

    check(article, 'CVE-2026-88771', quote, False)
    check(article, 'CVE-2026-88772', quote, False)


def test_all_group():
    article = (
        'CVE-2026-88771, CVE-2026-88772 and '
        'CVE-2026-88779 affect the product. '
        'All three vulnerabilities were exploited.'
    )

    quote = 'All three vulnerabilities were exploited'

    check(article, 'CVE-2026-88771', quote, True)
    check(article, 'CVE-2026-88772', quote, True)
    check(article, 'CVE-2026-88779', quote, True)


def test_one_of_ambiguous():
    article = (
        'CVE-2026-88771 and CVE-2026-88772 '
        'affect the product. '
        'One of the vulnerabilities was exploited.'
    )

    quote = 'One of the vulnerabilities was exploited'

    check(article, 'CVE-2026-88771', quote, False)
    check(article, 'CVE-2026-88772', quote, False)


def test_wrong_cve():
    article = (
        'CVE-2026-88771 affects Product A. '
        'CVE-2026-88772 was exploited as a zero-day.'
    )

    quote = 'exploited as a zero-day'

    check(article, 'CVE-2026-88771', quote, False)
    check(article, 'CVE-2026-88772', quote, True)


def test_missing_quote():
    article = 'CVE-2026-88779 affects NetScaler.'

    check(
        article,
        'CVE-2026-88779',
        'actively exploited as a zero-day',
        False,
    )


def main():
    tests = [
        test_direct_evidence,
        test_both_same_sentence,
        test_both_next_sentence,
        test_singular_reference,
        test_singular_ambiguous,
        test_all_group,
        test_one_of_ambiguous,
        test_wrong_cve,
        test_missing_quote,
    ]

    for test in tests:
        test()
        print(f'PASS: {test.__name__}')

    print(f'\nEvidence context tests passed: {len(tests)}')


if __name__ == '__main__':
    main()