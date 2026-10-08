import requests
import trafilatura


class ArticleFetchError(Exception):
    pass


class ArticleFetcher:
    def __init__(
        self,
        timeout: int = 20,
    ):
        self.timeout = timeout

    def fetch(
        self,
        url: str,
    ) -> str:
        if not url:
            raise ArticleFetchError(
                'Article URL is empty'
            )

        try:
            response = requests.get(
                url,
                headers={
                    'User-Agent': (
                        'Mozilla/5.0 '
                        '(compatible; VulnScout/0.1)'
                    ),
                },
                timeout=self.timeout,
            )

            response.raise_for_status()

        except requests.RequestException as error:
            raise ArticleFetchError(
                f'Failed to fetch article: {error}'
            ) from error

        text = trafilatura.extract(
            response.text,
            include_comments=False,
            include_tables=False,
            favor_precision=True,
        )

        if not text:
            raise ArticleFetchError(
                'Could not extract article text'
            )

        return text.strip()