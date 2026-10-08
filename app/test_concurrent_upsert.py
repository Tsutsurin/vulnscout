
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import delete, func, select

from app.database import SessionLocal
from app.models import Vulnerability
from app.services.vulnerability import VulnerabilityService


TEST_CVE = 'CVE-2099-99999'


def worker(barrier: Barrier) -> tuple[int, bool]:
    with SessionLocal() as session:
        service = VulnerabilityService(session)

        # Both workers start their INSERT attempts together.
        barrier.wait(timeout=15)

        db_vulnerability, created = (
            service._get_or_create_by_cve(TEST_CVE)
        )

        vulnerability_id = db_vulnerability.id

        session.commit()

        return vulnerability_id, created


def main() -> None:
    with SessionLocal() as session:
        existing = session.scalar(
            select(Vulnerability.id)
            .where(Vulnerability.cve == TEST_CVE)
        )

        if existing is not None:
            raise RuntimeError(
                f'Test CVE already exists: {TEST_CVE}'
            )

    barrier = Barrier(2)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(worker, barrier)
                for _ in range(2)
            ]

            results = [
                future.result(timeout=30)
                for future in futures
            ]

        print('CONCURRENT UPSERT RESULTS')
        print()

        for index, (vulnerability_id, created) in enumerate(
            results,
            start=1,
        ):
            print(
                f'Worker {index} | '
                f'ID: {vulnerability_id} | '
                f'Created: {created}'
            )

        with SessionLocal() as session:
            count = session.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(Vulnerability.cve == TEST_CVE)
            )

            ids = {
                vulnerability_id
                for vulnerability_id, _ in results
            }

            created_count = sum(
                created
                for _, created in results
            )

            assert count == 1, (
                f'Expected 1 row, got {count}'
            )

            assert len(ids) == 1, (
                f'Workers returned different IDs: {ids}'
            )

            assert created_count == 1, (
                f'Expected 1 creator, got {created_count}'
            )

        print()
        print('Concurrent UPSERT test PASSED')

    finally:
        # Remove only the record created by this test.
        with SessionLocal() as session:
            session.execute(
                delete(Vulnerability)
                .where(Vulnerability.cve == TEST_CVE)
            )
            session.commit()

        print('Test CVE cleanup completed')


if __name__ == '__main__':
    main()
