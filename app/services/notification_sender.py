import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.database import SessionLocal
from app.models_notification import Notification
from app.notifications.telegram import TelegramClient

logger = logging.getLogger(__name__)


class NotificationSender:
    MAX_ATTEMPTS = 5

    def __init__(self):
        self.client = TelegramClient()

    def process_pending(
        self,
        limit: int = 20,
    ) -> tuple[int, int]:
        if limit < 1:
            raise ValueError('limit must be positive')

        sent = 0
        failed = 0
        attempted_ids = set()

        for _ in range(limit):
            with SessionLocal.begin() as session:
                statement = (
                    select(Notification)
                    .where(
                        Notification.status.in_(
                            ['PENDING', 'FAILED']
                        ),
                        Notification.attempts < self.MAX_ATTEMPTS,
                    )
                )

                if attempted_ids:
                    statement = statement.where(
                        Notification.id.not_in(attempted_ids)
                    )

                statement = (
                    statement
                    .order_by(
                        Notification.created_at.asc(),
                        Notification.id.asc(),
                    )
                    .with_for_update(skip_locked=True)
                    .limit(1)
                )

                notification = session.scalar(statement)

                if notification is None:
                    break

                attempted_ids.add(notification.id)
                notification.attempts += 1

                try:
                    message_id = self.client.send(
                        notification.message
                    )

                    notification.status = 'SENT'
                    notification.sent_at = datetime.now(
                        timezone.utc
                    )
                    notification.last_error = None

                    sent += 1

                    logger.info(
                        'Telegram notification %s sent | '
                        'Message ID: %s',
                        notification.id,
                        message_id,
                    )

                except Exception as error:
                    notification.status = 'FAILED'
                    notification.last_error = (
                        f'{type(error).__name__}: {error}'
                    )[:2000]

                    failed += 1

                    logger.exception(
                        'Telegram notification %s failed',
                        notification.id,
                    )

        return sent, failed