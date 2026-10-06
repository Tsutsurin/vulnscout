from sqlalchemy import text

from app.database import engine


def main():
    with engine.connect() as connection:
        result = connection.execute(
            text(
                '''
                SELECT
                    current_database(),
                    current_user,
                    version()
                '''
            )
        )

        row = result.fetchone()

        print('VulnScout database connection OK')
        print(f'Database: {row[0]}')
        print(f'User: {row[1]}')
        print(f'PostgreSQL: {row[2]}')


if __name__ == '__main__':
    main()