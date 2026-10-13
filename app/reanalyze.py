
"""Manually reanalyze a publication without Telegram notifications."""

import argparse
import logging

from app.services.analysis_pipeline import AnalysisPipeline


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Reanalyze a VulnScout publication'
    )

    parser.add_argument(
        '--publication-id',
        type=int,
        required=True,
        help='Database ID of the publication',
    )

    args = parser.parse_args()

    if args.publication_id < 1:
        parser.error('--publication-id must be positive')

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
    )

    pipeline = AnalysisPipeline()

    try:
        result = pipeline.process_by_id(
            publication_id=args.publication_id,
            notify=False,
        )
    except (ValueError, RuntimeError) as error:
        parser.exit(1, f'Error: {error}\n')

    print()
    print('VULNSCOUT REANALYSIS')
    print(f'Publication ID: {result.publication_id}')
    print(f'Status: {result.status}')
    print(f'Accepted: {result.accepted}')
    print(f'Rejected: {result.rejected}')
    print(f'Saved CVEs: {", ".join(result.saved_cves) or "None"}')
    print('New Telegram notifications: disabled')

    if result.error:
        print(f'Error: {result.error}')

    if result.status == 'FAILED':
        raise SystemExit(1)


if __name__ == '__main__':
    main()