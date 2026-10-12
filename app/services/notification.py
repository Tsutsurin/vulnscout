import html

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import Publication, Vulnerability
from app.models_notification import Notification


class NotificationService:
    ZERO_DAY_STATUSES = {
        'POTENTIAL',
        'CONFIRMED',
    }

    def __init__(self, session: Session):
        self.session = session

    @classmethod
    def should_notify(
        cls,
        vulnerability: Vulnerability,
    ) -> bool:
        severity = (
            vulnerability.severity or ''
        ).strip().upper()

        score = vulnerability.cvss_score

        critical = (
            severity == 'CRITICAL'
            or (score is not None and score >= 9)
        )

        zero_day = (
            vulnerability.zero_day_status or ''
        ).upper() in cls.ZERO_DAY_STATUSES

        return critical or zero_day

    def enqueue(
        self,
        vulnerability: Vulnerability,
        publication: Publication,
    ) -> bool:
        if not self.should_notify(vulnerability):
            return False

        message = self.build_message(
            vulnerability,
            publication,
        )

        statement = (
            insert(Notification)
            .values(
                vulnerability_id=vulnerability.id,
                publication_id=publication.id,
                channel='TELEGRAM',
                status='PENDING',
                message=message,
                attempts=0,
            )
            .on_conflict_do_nothing(
                constraint='uq_notifications_vulnerability_channel',
            )
            .returning(Notification.id)
        )

        notification_id = self.session.scalar(statement)

        return notification_id is not None

    @staticmethod
    def build_message(
        vulnerability: Vulnerability,
        publication: Publication,
    ) -> str:
        def escape(value: object) -> str:
            return html.escape(str(value), quote=False)

        severity = (
            vulnerability.severity or 'UNKNOWN'
        ).upper()

        score = vulnerability.cvss_score

        zero_day = (
            vulnerability.zero_day_status or 'NONE'
        ).upper()

        critical = (
            severity == 'CRITICAL'
            or (score is not None and score >= 9)
        )

        potential_zero_day = zero_day in {
            'POTENTIAL',
            'CONFIRMED',
        }

        reasons = []

        if critical:
            reasons.append('Critical')

        if potential_zero_day:
            reasons.append('Потенциальный 0-day')

        heading = ' / '.join(reasons)

        cve = vulnerability.cve or 'Не присвоен'

        product = ' '.join(
            part
            for part in (
                vulnerability.vendor,
                vulnerability.product,
            )
            if part
        ) or 'Не определён'

        cvss = str(score) if score is not None else 'N/A'

        return (
            f'🚨 <b>VulnScout: {escape(heading)}</b>\n\n'
            f'<b>CVE:</b> {escape(cve)}\n'
            f'<b>Продукт:</b> {escape(product)}\n'
            f'<b>CVSS:</b> {escape(cvss)}\n'
            f'<b>Severity:</b> {escape(severity)}\n'
            f'<b>0-day:</b> {escape(zero_day)}\n'
            f'<b>0-day Score:</b> '
            f'{escape(vulnerability.zero_day_score)}\n'
            f'<b>Эксплуатация:</b> '
            f'{escape(vulnerability.exploitation_status)}\n'
            f'<b>Патч:</b> '
            f'{escape(vulnerability.patch_status)}\n\n'
            f'<b>Источник:</b>\n'
            f'{escape(publication.url)}\n\n'
            '<i>Оценка 0-day требует '
            'подтверждения аналитиком.</i>'
        )