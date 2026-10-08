from sqlalchemy import select

from app.database import SessionLocal
from app.models import Publication
from app.services.analysis_pipeline import AnalysisPipeline


def main():
    with SessionLocal() as session:
        publications = session.scalars(
            select(Publication)
            .order_by(
                Publication.published_at.desc()
            )
        ).all()

        pipeline = AnalysisPipeline(session)

        matched = 0
        skipped = 0
        errors = 0

        for publication in publications:
            result = pipeline.process(
                publication
            )

            if not result.matched:
                skipped += 1

                print(
                    f'SKIP  | '
                    f'{publication.title}'
                )

                continue

            matched += 1

            print()
            print(
                f'MATCH | '
                f'{publication.title}'
            )

            for match in result.product_matches:
                aliases = ', '.join(
                    match.matched_aliases
                )

                print(
                    f'      Product: '
                    f'{match.product.vendor} '
                    f'{match.product.name}'
                )

                print(
                    f'      Aliases: {aliases}'
                )

            if result.error:
                errors += 1

                print(
                    f'      ERROR: '
                    f'{result.error}'
                )

                continue

            if result.fetched:
                print(
                    '      Article: fetched'
                )
            else:
                print(
                    '      Article: cached'
                )

            print(
                f'      Characters: '
                f'{len(publication.raw_text or "")}'
            )

            if result.cves:
                print(
                    f'      CVEs: '
                    f'{", ".join(result.cves)}'
                )
            else:
                print(
                    '      CVEs: none'
                )

        session.commit()

        print()
        print('Analysis pipeline complete')
        print(f'Publications: {len(publications)}')
        print(f'Matched: {matched}')
        print(f'Skipped: {skipped}')
        print(f'Errors: {errors}')


if __name__ == '__main__':
    main()