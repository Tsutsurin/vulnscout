from openai import OpenAI

from app.config import (
    AI_API_KEY,
    AI_BASE_URL,
    AI_MODEL,
)


def main():
    client = OpenAI(
        api_key=AI_API_KEY,
        base_url=AI_BASE_URL,
    )

    response = client.responses.create(
        model=AI_MODEL,
        input=(
            'Return exactly this text: '
            'VulnScout AI connection OK'
        ),
    )

    print(response.output_text)


if __name__ == '__main__':
    main()