from dataclasses import dataclass
from datetime import datetime


@dataclass
class CollectedPublication:
    external_id: str
    feed_id: str
    source_name: str
    title: str
    url: str
    author: str | None
    published_at: datetime | None
    summary: str | None