
import argparse
import logging

from app.services.analysis_pipeline import AnalysisPipeline


def main() -> None:
    parser = argparse.ArgumentParser(
        description='VulnScout publication analysis'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=10,
        help='Maximum publications to process',
    )

    parser.add_argument(
        '--publication-id',
        type=int,
        default=None,
        help='Force analysis of one publication by ID',
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format=(
            '%(asctime)s | %(levelname)s | %(message)s'
        ),
    )

    pipeline = AnalysisPipeline()

    if args.publication_id is not None:
        results = [
            pipeline.process_by_id(
                args.publication_id
            )
        ]
    else:
        results = pipeline.process_pending(
            limit=args.limit
        )

    completed = 0
    skipped = 0
    failed = 0
    vulnerabilities = 0

    for result in results:
        print()
        print(
            f'Publication: {result.publication_id}'
        )
        print(
            f'Status: {result.status}'
        )

        if result.error:
            print(
                f'Error: {result.error}'
            )

        print(
            f'Accepted: {result.accepted}'
        )
        print(
            f'Rejected: {result.rejected}'
        )

        for cve in result.saved_cves:
            print(
                f'  {cve}'
            )

        if result.status == 'COMPLETED':
            completed += 1

        elif result.status == 'SKIPPED':
            skipped += 1

        elif result.status == 'FAILED':
            failed += 1

        vulnerabilities += len(
            result.saved_cves
        )

    print()
    print('PIPELINE SUMMARY')
    print(
        f'Processed: {len(results)}'
    )
    print(
        f'Completed: {completed}'
    )
    print(
        f'Skipped: {skipped}'
    )
    print(
        f'Failed: {failed}'
    )
    print(
        f'Vulnerabilities saved: {vulnerabilities}'
    )


if __name__ == '__main__':
    main()
