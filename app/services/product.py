from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import Product, ProductAlias


class ProductService:
    def __init__(self, session: Session):
        self.session = session

    def add_product(
        self,
        vendor: str,
        name: str,
        aliases: list[str] | None = None,
    ) -> Product:
        vendor = vendor.strip()
        name = name.strip()

        existing = self.session.scalar(
            select(Product).where(
                Product.vendor == vendor,
                Product.name == name,
            )
        )

        if existing:
            raise ValueError(
                f'Product already exists: {vendor} {name}'
            )

        product = Product(
            vendor=vendor,
            name=name,
            enabled=True,
        )

        self.session.add(product)
        self.session.flush()

        aliases = aliases or []

        normalized_aliases = {
            alias.strip()
            for alias in aliases
            if alias.strip()
        }

        normalized_aliases.add(name)

        for alias in sorted(normalized_aliases):
            product_alias = ProductAlias(
                product_id=product.id,
                alias=alias,
            )

            self.session.add(product_alias)

        self.session.flush()

        return product

    def get_products(
        self,
        enabled_only: bool = True,
    ) -> list[Product]:
        statement = (
            select(Product)
            .options(selectinload(Product.aliases))
            .order_by(Product.vendor, Product.name)
        )

        if enabled_only:
            statement = statement.where(
                Product.enabled.is_(True)
            )

        return list(
            self.session.scalars(statement).all()
        )

    def disable_product(
        self,
        product_id: int,
    ) -> bool:
        product = self.session.get(
            Product,
            product_id,
        )

        if not product:
            return False

        product.enabled = False

        return True