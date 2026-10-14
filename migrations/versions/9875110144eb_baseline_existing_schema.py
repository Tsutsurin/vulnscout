"""baseline existing schema

Revision ID: 9875110144eb
Revises: 
Create Date: 2026-10-06 16:29:05.741627

"""
from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = '9875110144eb'
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""


def downgrade() -> None:
    """Downgrade schema."""
