from app.database import SessionLocal
from app.services.product import ProductService


TEST_PRODUCTS = [
    {
        'vendor': 'Citrix',
        'name': 'NetScaler',
        'aliases': [
            'NetScaler ADC',
            'NetScaler Gateway',
            'Citrix ADC',
        ],
    },
]


def main():
    with SessionLocal() as session:
        service = ProductService(session)

        for data in TEST_PRODUCTS:
            try:
                product = service.add_product(
                    vendor=data['vendor'],
                    name=data['name'],
                    aliases=data['aliases'],
                )

                print(
                    f'Added: '
                    f'{product.vendor} {product.name}'
                )

            except ValueError as error:
                print(f'Skipped: {error}')

        session.commit()

        print()
        print('Product watchlist:')
        print()

        products = service.get_products()

        for product in products:
            aliases = ', '.join(
                alias.alias
                for alias in product.aliases
            )

            print(
                f'{product.id}: '
                f'{product.vendor} {product.name}'
            )
            print(f'   Aliases: {aliases}')


if __name__ == '__main__':
    main()