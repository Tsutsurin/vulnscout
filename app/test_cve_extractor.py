from sqlalchemy import select

from app.database import SessionLocal
from app.models import Publication
from app.services.article_fetcher import ArticleFetcher
from app.services.cve_extractor import CVEExtractor


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

        fetcher = ArticleFetcher()
        extractor = CVEExtractor()

        text = fetcher.fetch(
            publication.url
        )

        cves = extractor.extract(text)

        print(f'Title: {publication.title}')
        print(f'Characters: {len(text)}')
        print()
        print(f'CVEs found: {len(cves)}')

        for cve in cves:
            print(f'  {cve}')


if __name__ == '__main__':
    main()