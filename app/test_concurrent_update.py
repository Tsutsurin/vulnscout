
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import delete, select

from app.database import SessionLocal
from app.models import Vulnerability
from app.services.vulnerability import VulnerabilityService


TEST_CVE = 'CVE-2099-99998'


def worker(
    barrier: Barrier,
    score: int,
    exploitation: str,
) -> tuple[int, bool]:
    with SessionLocal() as session:
        service = VulnerabilityService(session)

        barrier.wait(timeout=15)

        db_vulnerability, created = (
            service._get_or_create_by_cve(TEST_CVE)
        )

        # Simulate the status merge while holding
        # the PostgreSQL row lock.
        priority = {
            'UNKNOWN': 0,
            'NONE': 1,
            'SUSPECTED': 2,
            'ACTIVE': 3,
        }

        current = (
            db_vulnerability.exploitation_status or 'UNKNOWN'
        )

        if priority[exploitation] > priority.get(current, 0):
            db_vulnerability.exploitation_status = exploitation

        db_vulnerability.zero_day_score = max(
            db_vulnerability.zero_day_score or 0,
            score,
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
                executor.submit(
                    worker,
                    barrier,
                    10,
                    'ACTIVE',
                ),
                executor.submit(
                    worker,
                    barrier,
                    5,
                    'SUSPECTED',
                ),
            ]

            results = [
                future.result(timeout=30)
                for future in futures
            ]

        with SessionLocal() as session:
            vulnerability = session.scalar(
                select(Vulnerability)
                .where(Vulnerability.cve == TEST_CVE)
            )

            assert vulnerability is not None
            assert vulnerability.zero_day_score == 10
            assert vulnerability.exploitation_status == 'ACTIVE'

            print('CONCURRENT UPDATE RESULTS')
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

            print()
            print(
                f'Final score: {vulnerability.zero_day_score}'
            )
            print(
                'Final exploitation status: '
                f'{vulnerability.exploitation_status}'
            )
            print()
            print('Concurrent UPDATE test PASSED')

    finally:
        with SessionLocal() as session:
            session.execute(
                delete(Vulnerability)
                .where(Vulnerability.cve == TEST_CVE)
            )
            session.commit()

        print('Test CVE cleanup completed')


if __name__ == '__main__':
    main()
