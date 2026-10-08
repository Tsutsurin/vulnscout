from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import Publication
from app.services.article_fetcher import (
    ArticleFetchError,
    ArticleFetcher,
)
from app.services.cve_extractor import CVEExtractor
from app.services.product_matcher import (
    ProductMatch,
    ProductMatcher,
)


@dataclass
class AnalysisResult:
    publication: Publication
    matched: bool
    product_matches: list[ProductMatch]
    cves: list[str]
    fetched: bool
    error: str | None = None


class AnalysisPipeline:
    def __init__(
        self,
        session: Session,
    ):
        self.session = session
        self.product_matcher = ProductMatcher(session)
        self.article_fetcher = ArticleFetcher()
        self.cve_extractor = CVEExtractor()

    def process(
        self,
        publication: Publication,
    ) -> AnalysisResult:
        product_matches = self.product_matcher.match(
            publication
        )

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

        cves = self.cve_extractor.extract(
            full_text
        )

        return AnalysisResult(
            publication=publication,
            matched=True,
            product_matches=product_matches,
            cves=cves,
            fetched=fetched,
        )