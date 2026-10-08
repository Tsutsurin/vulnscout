from sqlalchemy import select

from app.database import SessionLocal
from app.models import Publication
from app.services.article_fetcher import (
    ArticleFetchError,
    ArticleFetcher,
)


def main():
    with SessionLocal() as session:
        publication = session.scalar(
            select(Publication)
            .where(
                Publication.title.ilike(
                    '%NetScaler%'
                )
            )
            .order_by(
                Publication.published_at.desc()
            )
        )

        if not publication:
            print('Test publication not found')
            return

        print(f'Title: {publication.title}')
        print(f'URL: {publication.url}')
        print()

        fetcher = ArticleFetcher()

        try:
            text = fetcher.fetch(
                publication.url
            )
        except ArticleFetchError as error:
            print(f'ERROR: {error}')
            return

        print('ArticleFetcher OK')
        print(f'Characters: {len(text)}')
        print()
        print('--- ARTICLE PREVIEW ---')
        print()
        print(text[:3000])


if __name__ == '__main__':
    main()