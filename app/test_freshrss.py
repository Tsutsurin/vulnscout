from app.collectors.freshrss import FreshRSSClient


def main():
    client = FreshRSSClient()

    publications = client.collect(
        limit_per_feed=3,
    )

    print('FreshRSS collection OK')
    print(f'Publications found: {len(publications)}')
    print()

    for publication in publications:
        print(
            f'{publication.source_name} | '
            f'{publication.published_at} | '
            f'{publication.title}'
        )


if __name__ == '__main__':
    main()