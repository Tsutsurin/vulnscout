import argparse
import logging
import signal
import threading
from dataclasses import dataclass

from app.collectors.freshrss import FreshRSSClient
from app.database import SessionLocal
from app.services.analysis_pipeline import AnalysisPipeline
from app.services.notification_sender import NotificationSender
from app.services.publication import PublicationService

logger = logging.getLogger(__name__)


@dataclass
class WorkerStats:
    collected: int = 0
    inserted: int = 0
    duplicates: int = 0
    completed: int = 0
    skipped: int = 0
    failed: int = 0
    vulnerabilities: int = 0
    notifications_sent: int = 0
    notifications_failed: int = 0


class VulnScoutWorker:
    def __init__(
        self,
        limit_per_feed: int = 20,
        analysis_limit: int = 50,
    ):
        if limit_per_feed < 1:
            raise ValueError(
                'limit_per_feed must be positive'
            )

        if analysis_limit < 1:
            raise ValueError(
                'analysis_limit must be positive'
            )

        self.limit_per_feed = limit_per_feed
        self.analysis_limit = analysis_limit
        self.client = FreshRSSClient()
        self.pipeline = AnalysisPipeline()

    def collect_publications(
        self,
        stats: WorkerStats,
    ) -> None:
        logger.info(
            'Collecting publications from FreshRSS'
        )

        publications = self.client.collect(
            limit_per_feed=self.limit_per_feed
        )

        stats.collected = len(publications)

        logger.info(
            'Collected publications: %s',
            stats.collected,
        )

        for publication in publications:
            try:
                with SessionLocal.begin() as session:
                    service = PublicationService(session)
                    inserted = service.save(publication)

                if inserted:
                    stats.inserted += 1
                else:
                    stats.duplicates += 1

            except Exception:
                logger.exception(
                    'Failed to save publication: %s',
                    publication.title,
                )

        logger.info(
            'Ingestion complete | Inserted: %s | '
            'Duplicates or invalid: %s',
            stats.inserted,
            stats.duplicates,
        )

    def analyze_publications(
        self,
        stats: WorkerStats,
    ) -> None:
        logger.info('Starting analysis pipeline')

        results = self.pipeline.process_pending(
            limit=self.analysis_limit
        )

        for result in results:
            if result.status == 'COMPLETED':
                stats.completed += 1

            elif result.status == 'SKIPPED':
                stats.skipped += 1

            elif result.status == 'FAILED':
                stats.failed += 1

                logger.warning(
                    'Publication %s failed: %s',
                    result.publication_id,
                    result.error,
                )

            stats.vulnerabilities += len(
                result.saved_cves
            )

        logger.info(
            'Analysis complete | Completed: %s | '
            'Skipped: %s | Failed: %s | '
            'Saved findings: %s',
            stats.completed,
            stats.skipped,
            stats.failed,
            stats.vulnerabilities,
        )

    def send_notifications(
        self,
        stats: WorkerStats,
    ) -> None:
        logger.info(
            'Processing Telegram notifications'
        )

        sender = NotificationSender()

        sent, failed = sender.process_pending(
            limit=20
        )

        stats.notifications_sent = sent
        stats.notifications_failed = failed

        logger.info(
            'Telegram notifications | '
            'Sent: %s | Failed: %s',
            sent,
            failed,
        )

    def run_once(self) -> WorkerStats:
        stats = WorkerStats()

        logger.info(
            '========== VulnScout cycle started =========='
        )

        try:
            recovered = self.pipeline.recover_stale(
                timeout_minutes=30
            )

            if recovered:
                logger.warning(
                    'Recovered stale tasks: %s',
                    recovered,
                )

        except Exception:
            logger.exception(
                'Stale task recovery failed'
            )

        try:
            self.collect_publications(stats)

        except Exception:
            logger.exception(
                'FreshRSS collection failed'
            )

        try:
            self.analyze_publications(stats)

        except Exception:
            logger.exception(
                'Analysis pipeline failed'
            )

        try:
            self.send_notifications(stats)

        except Exception:
            logger.exception(
                'Telegram notification processing failed'
            )

        logger.info(
            '========== VulnScout cycle finished =========='
        )

        self.print_summary(stats)

        return stats

    @staticmethod
    def print_summary(
        stats: WorkerStats,
    ) -> None:
        print()
        print('VULNSCOUT WORKER SUMMARY')
        print(f'Collected: {stats.collected}')
        print(f'Inserted: {stats.inserted}')
        print(f'Duplicates/invalid: {stats.duplicates}')
        print(f'Completed: {stats.completed}')
        print(f'Skipped: {stats.skipped}')
        print(f'Failed: {stats.failed}')
        print(
            f'Vulnerabilities saved: '
            f'{stats.vulnerabilities}'
        )
        print(
            f'Telegram sent: '
            f'{stats.notifications_sent}'
        )
        print(
            f'Telegram failed: '
            f'{stats.notifications_failed}'
        )
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='VulnScout RSS and AI worker'
    )

    parser.add_argument(
        '--once',
        action='store_true',
        help='Run one cycle and exit',
    )

    parser.add_argument(
        '--interval',
        type=int,
        default=300,
        help='Seconds between cycles',
    )

    parser.add_argument(
        '--limit-per-feed',
        type=int,
        default=20,
        help='Maximum publications per RSS feed',
    )

    parser.add_argument(
        '--analysis-limit',
        type=int,
        default=50,
        help='Maximum publications analyzed per cycle',
    )

    args = parser.parse_args()

    if args.interval < 1:
        parser.error(
            '--interval must be positive'
        )

    logging.basicConfig(
        level=logging.INFO,
        format=(
            '%(asctime)s | %(levelname)s | %(message)s'
        ),
    )

    worker = VulnScoutWorker(
        limit_per_feed=args.limit_per_feed,
        analysis_limit=args.analysis_limit,
    )

    if args.once:
        worker.run_once()
        return

    stop_event = threading.Event()

    def stop_worker(signum, frame):
        logger.info('Shutdown requested')
        stop_event.set()

    signal.signal(
        signal.SIGINT,
        stop_worker,
    )

    signal.signal(
        signal.SIGTERM,
        stop_worker,
    )

    logger.info(
        'VulnScout worker started | Interval: %s seconds',
        args.interval,
    )

    while not stop_event.is_set():
        worker.run_once()

        if stop_event.wait(timeout=args.interval):
            break

    logger.info('VulnScout worker stopped')


if __name__ == '__main__':
    main()