import html

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import Publication, Vulnerability
from app.models_notification import Notification
from app.services.zero_day_scorer import ZeroDayScorer


class NotificationService:
    ZERO_DAY_STATUSES = {'POTENTIAL', 'CONFIRMED'}

    def __init__(self, session: Session):
        self.session = session

    @classmethod
    def should_notify(cls, vulnerability: Vulnerability) -> bool:
        severity = (vulnerability.severity or '').strip().upper()
        score = vulnerability.cvss_score
        critical = severity == 'CRITICAL' or (
            score is not None and score >= 9
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

        statement = (
            insert(Notification)
            .values(
                vulnerability_id=vulnerability.id,
                publication_id=publication.id,
                channel='TELEGRAM',
                status='PENDING',
                message=self.build_message(vulnerability, publication),
                attempts=0,
            )
            .on_conflict_do_nothing(
                constraint='uq_notifications_vulnerability_channel',
            )
            .returning(Notification.id)
        )
        return self.session.scalar(statement) is not None

    @staticmethod
    def build_message(
        vulnerability: Vulnerability,
        publication: Publication,
    ) -> str:
        def escape(value: object) -> str:
            return html.escape(str(value), quote=False)

        score = vulnerability.cvss_score
        severity = (vulnerability.severity or '').strip().upper()
        if severity in {'', 'UNKNOWN', 'N/A'} and score is not None:
            score_float = float(score)
            if score_float >= 9:
                severity = 'CRITICAL'
            elif score_float >= 7:
                severity = 'HIGH'
            elif score_float >= 4:
                severity = 'MEDIUM'
            elif score_float > 0:
                severity = 'LOW'
            else:
                severity = 'NONE'
        severity = severity or 'UNKNOWN'

        zero_day = (vulnerability.zero_day_status or 'NONE').upper()
        critical = severity == 'CRITICAL' or (
            score is not None and score >= 9
        )
        potential_zero_day = zero_day in {'POTENTIAL', 'CONFIRMED'}

        reasons = []
        if critical:
            reasons.append('Critical')
        if potential_zero_day:
            reasons.append('Потенциальный 0-day')
        heading = ' / '.join(reasons) or 'Уязвимость'

        vendor = (vulnerability.vendor or '').strip()
        product = (vulnerability.product or '').strip()
        if vendor and product.lower().startswith(vendor.lower() + ' '):
            product = product[len(vendor):].strip()
        display_product = ' '.join(
            part for part in (vendor, product) if part
        ) or 'Не определён'

        cvss = str(score) if score is not None else 'N/A'
        zero_day_score = vulnerability.zero_day_score or 0
        manual_review = (
            '\n\n<i>Оценка 0-day требует подтверждения аналитиком.</i>'
            if zero_day in {'SUSPICIOUS', 'POTENTIAL', 'CONFIRMED'}
            else ''
        )

        return (
            f'🚨 <b>VulnScout: {escape(heading)}</b>\n\n'
            f'<b>CVE:</b> {escape(vulnerability.cve or "Не присвоен")}\n'
            f'<b>Продукт:</b> {escape(display_product)}\n'
            f'<b>CVSS:</b> {escape(cvss)}\n'
            f'<b>Severity:</b> {escape(severity)}\n'
            f'<b>0-day:</b> {escape(zero_day)}\n'
            f'<b>0-day Score:</b> {escape(zero_day_score)}/{ZeroDayScorer.MAX_SCORE}\n'
            f'<b>Эксплуатация:</b> '
            f'{escape(vulnerability.exploitation_status or "UNKNOWN")}\n'
            f'<b>Патч:</b> '
            f'{escape(vulnerability.patch_status or "UNKNOWN")}\n\n'
            f'<b>Источник:</b>\n{escape(publication.url)}'
            f'{manual_review}'
        )
