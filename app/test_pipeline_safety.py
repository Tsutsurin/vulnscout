
import unittest
from unittest.mock import MagicMock, patch

from app.models import Vulnerability, VulnerabilityPublication
from app.services.analysis_pipeline import AnalysisPipeline
from app.services.vulnerability import VulnerabilityService


class TestExploitationRecalculation(unittest.TestCase):

    @staticmethod
    def make_link(status, quote):
        return VulnerabilityPublication(
            evidence={
                'exploitation_status': status,
                'exploitation': quote,
            },
            score_reasons=[],
        )

    def test_active_evidence(self):
        link = self.make_link(
            'ACTIVE',
            'actively exploited in the wild',
        )

        result = VulnerabilityService._exploitation_from_link(
            link
        )

        self.assertEqual(result, 'ACTIVE')

    def test_missing_evidence(self):
        link = self.make_link('ACTIVE', None)

        result = VulnerabilityService._exploitation_from_link(
            link
        )

        self.assertEqual(result, 'UNKNOWN')

    def test_legacy_link(self):
        link = VulnerabilityPublication(
            evidence={
                'exploitation': 'actively exploited',
            },
            score_reasons=[],
        )

        result = VulnerabilityService._exploitation_from_link(
            link
        )

        self.assertEqual(result, 'UNKNOWN')

    def test_active_to_unknown(self):
        vulnerability = Vulnerability(
            cve='CVE-2099-0001',
            exploitation_status='ACTIVE',
        )

        link = self.make_link('ACTIVE', None)

        service = VulnerabilityService(MagicMock())
        service._get_links = MagicMock(return_value=[link])

        service._recalculate_exploitation(vulnerability)

        self.assertEqual(
            vulnerability.exploitation_status,
            'UNKNOWN',
        )

    def test_other_publication_preserves_active(self):
        vulnerability = Vulnerability(
            cve='CVE-2099-0001',
            exploitation_status='ACTIVE',
        )

        links = [
            self.make_link('UNKNOWN', None),
            self.make_link(
                'ACTIVE',
                'actively exploited in the wild',
            ),
        ]

        service = VulnerabilityService(MagicMock())
        service._get_links = MagicMock(return_value=links)

        service._recalculate_exploitation(vulnerability)

        self.assertEqual(
            vulnerability.exploitation_status,
            'ACTIVE',
        )


class TestPipelineFailure(unittest.TestCase):

    def test_failed_analysis_is_recorded(self):
        pipeline = AnalysisPipeline()

        with (
            patch.object(
                pipeline,
                '_analyze_publication',
                side_effect=RuntimeError(
                    'Groq temporarily unavailable'
                ),
            ),
            patch.object(
                pipeline,
                '_mark_failed',
            ) as mark_failed,
        ):
            result = pipeline._process_claimed(
                publication_id=999,
                notify=False,
            )

        self.assertEqual(result.status, 'FAILED')
        self.assertEqual(result.publication_id, 999)

        assert result.error is not None

        self.assertIn(
            'Groq temporarily unavailable',
            result.error,
        )

        mark_failed.assert_called_once()

        args = mark_failed.call_args.args

        self.assertEqual(args[0], 999)
        self.assertIn(
            'Groq temporarily unavailable',
            args[1],
        )

    def test_failure_does_not_send_notifications(self):
        pipeline = AnalysisPipeline()

        with (
            patch.object(
                pipeline,
                '_analyze_publication',
                side_effect=RuntimeError('AI failure'),
            ),
            patch.object(pipeline, '_mark_failed'),
            patch(
                'app.services.analysis_pipeline.NotificationService'
            ) as notification_service,
        ):
            result = pipeline._process_claimed(
                publication_id=999,
                notify=False,
            )

        self.assertEqual(result.status, 'FAILED')
        notification_service.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)