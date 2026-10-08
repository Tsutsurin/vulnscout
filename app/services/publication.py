import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.models import CollectedPublication
from app.models import Publication, Source


class PublicationService:
    def __init__(self, session: Session):
        self.session = session

    def _get_or_create_source(
        self,
        publication: CollectedPublication,
    ) -> Source:
        source = self.session.scalar(
            select(Source).where(
                Source.url == publication.source_url
            )
        )

        if source:
            return source

        source = Source(
            name=publication.source_name,
            type='RSS',
            url=publication.source_url,
            enabled=True,
        )

        self.session.add(source)
        self.session.flush()

        return source

    def _content_hash(
        self,
        publication: CollectedPublication,
    ) -> str:
        content = (
            f'{publication.title}\n'
            f'{publication.summary or ""}'
        )

        return hashlib.sha256(
            content.encode('utf-8')
        ).hexdigest()

    def save(
        self,
        publication: CollectedPublication,
    ) -> bool:
        if not publication.url:
            return False

        source = self._get_or_create_source(publication)

        existing = self.session.scalar(
            select(Publication).where(
                Publication.source_id == source.id,
                Publication.url == publication.url,
            )
        )

        if existing:
            return False

        db_publication = Publication(
            source_id=source.id,
            url=publication.url,
            title=publication.title,
            author=publication.author,
            published_at=publication.published_at,
            raw_text=None,
            raw_data={
                'external_id': publication.external_id,
                'feed_id': publication.feed_id,
                'summary': publication.summary,
            },
            content_hash=self._content_hash(publication),
        )

        self.session.add(db_publication)

        return True