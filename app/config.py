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