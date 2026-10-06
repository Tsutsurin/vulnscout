from sqlalchemy import select

from app.database import SessionLocal
from app.models import Source


def main():
    with SessionLocal() as session:
        sources = session.scalars(
            select(Source).order_by(Source.id)
        ).all()

        print('VulnScout database connection OK')
        print(f'Sources found: {len(sources)}')

        for source in sources:
            print(
                f'{source.id}: '
                f'{source.name} | '
                f'{source.type} | '
                f'enabled={source.enabled}'
            )


if __name__ == '__main__':
    main()