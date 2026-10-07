from sqlalchemy import select

from app.database import SessionLocal
from app.models import Publication
from app.services.product_matcher import ProductMatcher


def main():
    with SessionLocal() as session:
        matcher = ProductMatcher(session)

        publications = session.scalars(
            select(Publication)
            .order_by(Publication.published_at.desc())
        ).all()

        matched_count = 0
        skipped_count = 0

        for publication in publications:
            matches = matcher.match(publication)

            if not matches:
                skipped_count += 1

                print(
                    f'SKIP  | '
                    f'{publication.title}'
                )
                continue

            matched_count += 1

            products = []

            for match in matches:
                aliases = ', '.join(match.matched_aliases)

                products.append(
                    f'{match.product.vendor} '
                    f'{match.product.name} '
                    f'[{aliases}]'
                )

            print(
                f'MATCH | '
                f'{publication.title}'
            )

            for product in products:
                print(f'      -> {product}')

        print()
        print('Product matching complete')
        print(f'Publications: {len(publications)}')
        print(f'Matched: {matched_count}')
        print(f'Skipped: {skipped_count}')


if __name__ == '__main__':
    main()