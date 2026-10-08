
from sqlalchemy import select

from app.ai.client import AIClient
from app.ai.validator import AIResultValidator
from app.database import SessionLocal
from app.models import Publication
from app.services.cve_extractor import CVEExtractor
from app.services.product_matcher import ProductMatcher
from app.services.vulnerability import VulnerabilityService
from app.services.zero_day_scorer import ZeroDayScorer


def main():
    with SessionLocal() as session:
        publication = session.scalar(
            select(Publication)
            .where(
                Publication.title.ilike('%NetScaler%')
            )
            .order_by(
                Publication.published_at.desc()
            )
        )

        if not publication:
            print('Publication not found')
            return

        if not publication.raw_text:
            print('Full article text not found')
            return

        matcher = ProductMatcher(session)
        extractor = CVEExtractor()

        matches = matcher.match(publication)

        products = [
            f'{match.product.vendor} '
            f'{match.product.name}'
            for match in matches
        ]

        cves = extractor.extract(
            publication.raw_text
        )

        print(f'Title: {publication.title}')
        print(f'Products: {", ".join(products)}')
        print(f'CVEs: {", ".join(cves)}')

        print()
        print('Sending article to AI...')
        print()

        client = AIClient()

        result = client.analyze(
            products=products,
            cves=cves,
            article_text=publication.raw_text,
        )

        print('AI RESPONSE')
        print()

        print(
            result.model_dump_json(
                indent=2
            )
        )

        print()
        print('VALIDATION')
        print()

        validator = AIResultValidator()

        validation = validator.validate(
            result=result,
            article_text=publication.raw_text,
            extracted_cves=cves,
        )

        print(
            f'Accepted: {len(validation.accepted)}'
        )
        print(
            f'Rejected: {len(validation.rejected)}'
        )

        for issue in validation.issues:
            print(
                f'  {issue.cve} | '
                f'{issue.field} | '
                f'{issue.message}'
            )

        print()
        print('ZERO-DAY SCORING')
        print()

        scorer = ZeroDayScorer()

        for vulnerability in validation.accepted:
            score_result = scorer.score(
                vulnerability
            )

            print(
                f'{vulnerability.cve or "NO CVE"}'
            )
            print(
                f'  Score: {score_result.score}'
            )
            print(
                f'  Status: {score_result.status.value}'
            )
            print('  Reasons:')

            if not score_result.reasons:
                print('    none')

            for reason in score_result.reasons:
                sign = (
                    '+'
                    if reason.points >= 0
                    else ''
                )

                print(
                    f'    {sign}{reason.points} '
                    f'{reason.signal}'
                )

            print()

        print()
        print('DATABASE PERSISTENCE')
        print()

        service = VulnerabilityService(session)

        try:
            for vulnerability in validation.accepted:
                score_result = scorer.score(
                    vulnerability
                )

                saved = service.save_analysis(
                    publication=publication,
                    vulnerability=vulnerability,
                    score_result=score_result,
                )

                print(
                    f'{saved.vulnerability.cve or "NO CVE"} | '
                    f'ID: {saved.vulnerability.id} | '
                    f'Created: {saved.created} | '
                    f'Linked: {saved.linked}'
                )

            session.commit()

        except Exception:
            session.rollback()
            raise

        print()
        print('Database commit successful')


if __name__ == '__main__':
    main()
