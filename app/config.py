import os

from dotenv import load_dotenv


load_dotenv()


POSTGRES_HOST = os.getenv('POSTGRES_HOST', '127.0.0.1')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'vulnscout')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'vulnscout')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')


if not POSTGRES_PASSWORD:
    raise RuntimeError('POSTGRES_PASSWORD is not configured')


DATABASE_URL = (
    f'postgresql+psycopg://'
    f'{POSTGRES_USER}:{POSTGRES_PASSWORD}'
    f'@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}'
)


FRESHRSS_URL = os.getenv(
    'FRESHRSS_URL',
    'http://127.0.0.1:8080/api/greader.php',
)
FRESHRSS_USERNAME = os.getenv('FRESHRSS_USERNAME')
FRESHRSS_API_PASSWORD = os.getenv('FRESHRSS_API_PASSWORD')

if not FRESHRSS_USERNAME:
    raise RuntimeError('FRESHRSS_USERNAME is not configured')

if not FRESHRSS_API_PASSWORD:
    raise RuntimeError('FRESHRSS_API_PASSWORD is not configured')


AI_BASE_URL = os.getenv(
    'AI_BASE_URL',
    'https://api.groq.com/openai/v1',
)

AI_API_KEY = os.getenv('AI_API_KEY')

AI_MODEL = os.getenv(
    'AI_MODEL',
    'openai/gpt-oss-120b',
)

if not AI_API_KEY:
    raise RuntimeError(
        'AI_API_KEY is not configured'
    )