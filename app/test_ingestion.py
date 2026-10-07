from app.collectors.freshrss import FreshRSSClient
from app.database import SessionLocal
from app.services.publication import PublicationService


def main():
    client = FreshRSSClient()

    publications = client.collect(
        limit_per_feed=3,
    )

    inserted = 0
    skipped = 0

    with SessionLocal() as session:
        service = PublicationService(session)

        for publication in publications:
            if service.save(publication):
                inserted += 1
            else:
                skipped += 1

        session.commit()

    print('VulnScout RSS ingestion OK')
    print(f'Collected: {len(publications)}')
    print(f'Inserted: {inserted}')
    print(f'Skipped: {skipped}')


if __name__ == '__main__':
    main()