from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import Product, Publication
from app.services.product import ProductService


@dataclass
class ProductMatch:
    product: Product
    matched_aliases: list[str]


class ProductMatcher:
    def __init__(self, session: Session):
        self.product_service = ProductService(session)

    def match(
        self,
        publication: Publication,
    ) -> list[ProductMatch]:
        summary = None

        if publication.raw_data:
            summary = publication.raw_data.get('summary')

        text = ' '.join(
            part
            for part in [
                publication.title,
                summary,
            ]
            if part
        ).lower()

        matches = []

        for product in self.product_service.get_products():
            matched_aliases = []

            for alias in product.aliases:
                if alias.alias.lower() in text:
                    matched_aliases.append(alias.alias)

            if matched_aliases:
                matches.append(
                    ProductMatch(
                        product=product,
                        matched_aliases=matched_aliases,
                    )
                )

        return matches