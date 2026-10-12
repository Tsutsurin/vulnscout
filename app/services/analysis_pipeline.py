import logging

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.ai.client import AIClient
from app.ai.validator import AIResultValidator
from app.database import SessionLocal
from app.models import Publication
from app.services.article_fetcher import (
    ArticleFetchError,
    ArticleFetcher,
)
from app.services.cve_extractor import CVEExtractor
from app.services.notification import NotificationService
from app.services.product_matcher import (
    ProductMatch,
    ProductMatcher,
)
from app.services.vulnerability import VulnerabilityService
from app.services.zero_day_scorer import ZeroDayScorer


logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    publication: Publication
    matched: bool
    product_matches: list[ProductMatch]
    cves: list[str]
    fetched: bool
    error: str | None = None


@dataclass
class PipelineResult:
    publication_id: int
    status: str
    accepted: int = 0
    rejected: int = 0
    saved_cves: list[str] = field(default_factory=list)
    error: str | None = None


class AnalysisPipeline:
    MAX_ATTEMPTS = 3

    def __init__(self, session: Session | None = None):
        self.session = session
        self.article_fetcher = ArticleFetcher()
        self.cve_extractor = CVEExtractor()
        self.validator = AIResultValidator()
        self.scorer = ZeroDayScorer()

    def process(self, publication: Publication) -> AnalysisResult:
        if self.session is None:
            raise RuntimeError(
                'process() requires a database session'
            )

        matcher = ProductMatcher(self.session)
        product_matches = matcher.match(publication)

        if not product_matches:
            return AnalysisResult(
                publication=publication,
                matched=False,
                product_matches=[],
                cves=[],
                fetched=False,
            )

        fetched = False

        if publication.raw_text:
            full_text = publication.raw_text
        else:
            try:
                full_text = self.article_fetcher.fetch(
                    publication.url
                )
                publication.raw_text = full_text
                fetched = True

            except ArticleFetchError as error:
                return AnalysisResult(
                    publication=publication,
                    matched=True,
                    product_matches=product_matches,
                    cves=[],
                    fetched=False,
                    error=str(error),
                )

        cves = self.cve_extractor.extract(full_text)

        return AnalysisResult(
            publication=publication,
            matched=True,
            product_matches=product_matches,
            cves=cves,
            fetched=fetched,
        )

    def process_pending(
        self,
        limit: int = 10,
    ) -> list[PipelineResult]:
        if limit < 1:
            raise ValueError('limit must be positive')

        results = []
        attempted_ids = set()

        for _ in range(limit):
            publication_id = self._claim_next(
                exclude_ids=attempted_ids
            )

            if publication_id is None:
                break

            attempted_ids.add(publication_id)

            results.append(
                self._process_claimed(publication_id)
            )

        return results

    def process_by_id(
        self,
        publication_id: int,
    ) -> PipelineResult:
        if publication_id < 1:
            raise ValueError(
                'publication_id must be positive'
            )

        with SessionLocal.begin() as session:
            publication = session.get(
                Publication,
                publication_id,
                with_for_update=True,
            )

            if publication is None:
                raise ValueError(
                    f'Publication {publication_id} not found'
                )

            if publication.analysis_status == 'PROCESSING':
                raise RuntimeError(
                    f'Publication {publication_id} '
                    'is already being processed'
                )

            publication.analysis_status = 'PROCESSING'
            publication.analysis_attempts += 1
            publication.analysis_error = None
            publication.analysis_started_at = (
                datetime.now(timezone.utc)
            )

        logger.info(
            'Publication %s manually claimed',
            publication_id,
        )

        return self._process_claimed(publication_id)

    def _claim_next(
        self,
        exclude_ids: set[int] | None = None,
    ) -> int | None:
        with SessionLocal.begin() as session:
            statement = select(Publication).where(
                Publication.analysis_status.in_(
                    ['PENDING', 'FAILED']
                ),
                Publication.analysis_attempts < self.MAX_ATTEMPTS,
            )

            if exclude_ids:
                statement = statement.where(
                    Publication.id.not_in(exclude_ids)
                )

            statement = (
                statement
                .order_by(
                    Publication.collected_at.asc(),
                    Publication.id.asc(),
                )
                .with_for_update(skip_locked=True)
                .limit(1)
            )

            publication = session.scalar(statement)

            if publication is None:
                return None

            publication.analysis_status = 'PROCESSING'
            publication.analysis_attempts += 1
            publication.analysis_error = None
            publication.analysis_started_at = (
                datetime.now(timezone.utc)
            )

            publication_id = publication.id

        logger.info(
            'Publication %s claimed for analysis',
            publication_id,
        )

        return publication_id

    def _process_claimed(
        self,
        publication_id: int,
    ) -> PipelineResult:
        try:
            return self._analyze_publication(
                publication_id
            )

        except Exception as error:
            logger.exception(
                'Publication %s analysis failed',
                publication_id,
            )

            message = (
                f'{type(error).__name__}: {error}'
            )[:2000]

            try:
                self._mark_failed(
                    publication_id,
                    message,
                )
            except Exception:
                logger.exception(
                    'Could not mark publication %s as FAILED',
                    publication_id,
                )

            return PipelineResult(
                publication_id=publication_id,
                status='FAILED',
                error=message,
            )

    def _analyze_publication(
        self,
        publication_id: int,
    ) -> PipelineResult:
        with SessionLocal() as session:
            publication = session.get(
                Publication,
                publication_id,
            )

            if publication is None:
                raise RuntimeError(
                    f'Publication {publication_id} not found'
                )

            matcher = ProductMatcher(session)
            matches = matcher.match(publication)

            products = list(
                dict.fromkeys(
                    f'{match.product.vendor} '
                    f'{match.product.name}'
                    for match in matches
                )
            )

            article_url = publication.url
            full_text = publication.raw_text

        logger.info(
            'Publication %s | Matched products: %s',
            publication_id,
            products,
        )

        if not products:
            self._mark_skipped(publication_id)

            logger.info(
                'Publication %s skipped: '
                'no tracked products',
                publication_id,
            )

            return PipelineResult(
                publication_id=publication_id,
                status='SKIPPED',
            )

        fetched = False

        if not full_text:
            logger.info(
                'Publication %s | Fetching article',
                publication_id,
            )

            full_text = self.article_fetcher.fetch(
                article_url
            )
            fetched = True

        cves = self.cve_extractor.extract(full_text)

        logger.info(
            'Publication %s | Extracted CVEs: %s',
            publication_id,
            cves,
        )

        logger.info(
            'Publication %s | Sending article to AI',
            publication_id,
        )

        client = AIClient()

        ai_result = client.analyze(
            products=products,
            cves=cves,
            article_text=full_text,
        )

        validation = self.validator.validate(
            result=ai_result,
            article_text=full_text,
            extracted_cves=cves,
        )

        logger.info(
            'Publication %s | AI findings: %s | '
            'Accepted: %s | Rejected: %s',
            publication_id,
            len(ai_result.vulnerabilities),
            len(validation.accepted),
            len(validation.rejected),
        )

        for issue in validation.issues:
            logger.warning(
                'Publication %s | %s | %s | %s',
                publication_id,
                issue.cve,
                issue.field,
                issue.message,
            )

        if validation.rejected and not validation.accepted:
            issues = '; '.join(
                f'{issue.cve}: '
                f'{issue.field}: '
                f'{issue.message}'
                for issue in validation.issues[:5]
            )

            raise RuntimeError(
                f'All AI findings rejected: {issues}'
            )

        saved_cves = []
        queued_count = 0

        with SessionLocal.begin() as session:
            publication = session.get(
                Publication,
                publication_id,
                with_for_update=True,
            )

            if publication is None:
                raise RuntimeError(
                    f'Publication {publication_id} not found'
                )

            if publication.analysis_status != 'PROCESSING':
                raise RuntimeError(
                    'Publication is no longer PROCESSING'
                )

            if fetched:
                publication.raw_text = full_text

            service = VulnerabilityService(session)
            notification_service = NotificationService(
                session
            )

            for vulnerability in validation.accepted:
                score_result = self.scorer.score(
                    vulnerability
                )

                saved = service.save_analysis(
                    publication=publication,
                    vulnerability=vulnerability,
                    score_result=score_result,
                )

                saved_cves.append(
                    saved.vulnerability.cve
                    or f'NO-CVE:{saved.vulnerability.id}'
                )

                queued = notification_service.enqueue(
                    vulnerability=saved.vulnerability,
                    publication=publication,
                )

                if queued:
                    queued_count += 1

                    logger.info(
                        'Publication %s | '
                        'Telegram notification queued: %s',
                        publication_id,
                        saved.vulnerability.cve,
                    )

            publication.analysis_status = 'COMPLETED'
            publication.analysis_error = None
            publication.analysis_started_at = None
            publication.analyzed_at = datetime.now(
                timezone.utc
            )

        logger.info(
            'Publication %s | Completed | '
            'Saved vulnerabilities: %s | '
            'Notifications queued: %s',
            publication_id,
            len(saved_cves),
            queued_count,
        )

        return PipelineResult(
            publication_id=publication_id,
            status='COMPLETED',
            accepted=len(validation.accepted),
            rejected=len(validation.rejected),
            saved_cves=saved_cves,
        )

    @staticmethod
    def _mark_skipped(
        publication_id: int,
    ) -> None:
        with SessionLocal.begin() as session:
            publication = session.get(
                Publication,
                publication_id,
                with_for_update=True,
            )

            if publication is None:
                raise RuntimeError(
                    f'Publication {publication_id} not found'
                )

            if publication.analysis_status != 'PROCESSING':
                raise RuntimeError(
                    'Publication is no longer PROCESSING'
                )

            publication.analysis_status = 'SKIPPED'
            publication.analysis_error = None
            publication.analysis_started_at = None
            publication.analyzed_at = datetime.now(
                timezone.utc
            )

    @staticmethod
    def _mark_completed(
        publication_id: int,
    ) -> None:
        with SessionLocal.begin() as session:
            publication = session.get(
                Publication,
                publication_id,
                with_for_update=True,
            )

            if publication is None:
                raise RuntimeError(
                    f'Publication {publication_id} not found'
                )

            if publication.analysis_status != 'PROCESSING':
                raise RuntimeError(
                    'Publication is no longer PROCESSING'
                )

            publication.analysis_status = 'COMPLETED'
            publication.analysis_error = None
            publication.analysis_started_at = None
            publication.analyzed_at = datetime.now(
                timezone.utc
            )

    @staticmethod
    def _mark_failed(
        publication_id: int,
        message: str,
    ) -> None:
        with SessionLocal.begin() as session:
            session.execute(
                update(Publication)
                .where(
                    Publication.id == publication_id,
                    Publication.analysis_status == 'PROCESSING',
                )
                .values(
                    analysis_status='FAILED',
                    analysis_error=message,
                    analysis_started_at=None,
                )
            )

    @staticmethod
    def recover_stale(
        timeout_minutes: int = 30,
    ) -> int:
        if timeout_minutes < 1:
            raise ValueError(
                'timeout_minutes must be positive'
            )

        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(minutes=timeout_minutes)
        )

        with SessionLocal.begin() as session:
            statement = (
                update(Publication)
                .where(
                    Publication.analysis_status == 'PROCESSING',
                    Publication.analysis_started_at.is_not(None),
                    Publication.analysis_started_at < cutoff,
                )
                .values(
                    analysis_status='FAILED',
                    analysis_error='Processing timeout',
                    analysis_started_at=None,
                )
                .returning(Publication.id)
            )

            recovered_ids = session.scalars(
                statement
            ).all()

        if recovered_ids:
            logger.warning(
                'Recovered stale publications: %s',
                recovered_ids,
            )

        return len(recovered_ids)