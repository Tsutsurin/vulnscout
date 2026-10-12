import os

import requests


class TelegramError(Exception):
    pass


class TelegramClient:
    BASE_URL = 'https://api.telegram.org'

    def __init__(self):
        self.token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.chat_id = os.getenv('TELEGRAM_CHAT_ID')

        if not self.token:
            raise TelegramError(
                'TELEGRAM_BOT_TOKEN is not configured'
            )

        if not self.chat_id:
            raise TelegramError(
                'TELEGRAM_CHAT_ID is not configured'
            )

    def send(self, message: str) -> int:
        url = (
            f'{self.BASE_URL}/bot{self.token}/sendMessage'
        )

        try:
            response = requests.post(
                url,
                json={
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': 'HTML',
                    'disable_web_page_preview': True,
                },
                timeout=20,
            )

            response.raise_for_status()

            data = response.json()

            if not data.get('ok'):
                raise TelegramError(
                    data.get(
                        'description',
                        'Telegram API returned an error',
                    )
                )

            return data['result']['message_id']

        except (
            requests.RequestException,
            ValueError,
            KeyError,
        ) as error:
            raise TelegramError(
                f'Telegram request failed: {error}'
            ) from error