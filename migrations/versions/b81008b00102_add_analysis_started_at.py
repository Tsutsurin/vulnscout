from alembic import op
import sqlalchemy as sa


revision = 'b81008b00102'
down_revision = 'a81008b00101'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'publications',
        sa.Column(
            'analysis_started_at',
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column(
        'publications',
        'analysis_started_at',
    )
