
"""Add publication analysis status.

Revision ID: a81008b00101
Revises: 59a9925f2b71
"""

import sqlalchemy as sa
from alembic import op

revision = 'a81008b00101'
down_revision = '59a9925f2b71'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'publications',
        sa.Column(
            'analysis_status',
            sa.String(length=20),
            nullable=False,
            server_default='PENDING',
        ),
    )

    op.add_column(
        'publications',
        sa.Column(
            'analysis_attempts',
            sa.Integer(),
            nullable=False,
            server_default='0',
        ),
    )

    op.add_column(
        'publications',
        sa.Column(
            'analysis_error',
            sa.Text(),
            nullable=True,
        ),
    )

    op.add_column(
        'publications',
        sa.Column(
            'analyzed_at',
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.create_index(
        'idx_publications_analysis_status',
        'publications',
        ['analysis_status'],
    )


def downgrade() -> None:
    op.drop_index(
        'idx_publications_analysis_status',
        table_name='publications',
    )

    op.drop_column(
        'publications',
        'analyzed_at',
    )

    op.drop_column(
        'publications',
        'analysis_error',
    )

    op.drop_column(
        'publications',
        'analysis_attempts',
    )

    op.drop_column(
        'publications',
        'analysis_status',
    )
