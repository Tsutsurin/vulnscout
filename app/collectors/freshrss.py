from datetime import datetime, timezone

import requests

from app.collectors.models import CollectedPublication
from app.config import (
    FRESHRSS_API_PASSWORD,
    FRESHRSS_URL,
    FRESHRSS_USERNAME,
)


class FreshRSSClient:
    def __init__(self):
        self.base_url = FRESHRSS_URL.rstrip('/')
        self.token = None

    def authenticate(self):
        response = requests.post(
            f'{self.base_url}/accounts/ClientLogin',
            data={
                'Email': FRESHRSS_USERNAME,
                'Passwd': FRESHRSS_API_PASSWORD,
            },
            timeout=15,
        )
        response.raise_for_status()

        values = {}

        for line in response.text.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                values[key] = value

        token = values.get('Auth')

        if not token:
            raise RuntimeError(
                'FreshRSS authentication succeeded '
                'but Auth token was not returned'
            )

        self.token = token

    def _headers(self):
        if not self.token:
            self.authenticate()

        return {
            'Authorization': f'GoogleLogin auth={self.token}',
        }

    def get_subscriptions(self):
        response = requests.get(
            f'{self.base_url}/reader/api/0/subscription/list',
            headers=self._headers(),
            params={
                'output': 'json',
            },
            timeout=15,
        )
        response.raise_for_status()

        return response.json().get('subscriptions', [])

    def get_publications(
        self,
        feed_id: str,
        limit: int = 10,
    ) -> list[CollectedPublication]:
        response = requests.get(
            f'{self.base_url}/reader/api/0/stream/contents/{feed_id}',
            headers=self._headers(),
            params={
                'n': limit,
                'output': 'json',
            },
            timeout=15,
        )
        response.raise_for_status()

        data = response.json()
        publications = []

        for item in data.get('items', []):
            url = None

            canonical = item.get('canonical', [])

            if canonical:
                url = canonical[0].get('href')

            if not url:
                alternate = item.get('alternate', [])

                if alternate:
                    url = alternate[0].get('href')

            published = item.get('published')

            published_at = (
                datetime.fromtimestamp(
                    published,
                    tz=timezone.utc,
                )
                if published
                else None
            )

            origin = item.get('origin', {})
            summary = item.get('summary', {})

            publication = CollectedPublication(
                external_id=item['id'],
                feed_id=origin.get('streamId', feed_id),
                source_name=origin.get('title', ''),
                title=item.get('title', ''),
                url=url or '',
                author=item.get('author'),
                published_at=published_at,
                summary=summary.get('content'),
            )

            publications.append(publication)

        return publications

    def collect(
        self,
        limit_per_feed: int = 10,
    ) -> list[CollectedPublication]:
        publications = []

        subscriptions = self.get_subscriptions()

        for subscription in subscriptions:
            feed_id = subscription.get('id')

            if not feed_id:
                continue

            feed_publications = self.get_publications(
                feed_id=feed_id,
                limit=limit_per_feed,
            )

            publications.extend(feed_publications)

        return publications