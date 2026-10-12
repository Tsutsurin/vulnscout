from alembic import op
import sqlalchemy as sa


revision = 'c81008b00103'
down_revision = 'b81008b00102'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'notifications',
        sa.Column(
            'id',
            sa.BigInteger(),
            sa.Identity(),
            primary_key=True,
        ),
        sa.Column(
            'vulnerability_id',
            sa.BigInteger(),
            sa.ForeignKey(
                'vulnerabilities.id',
                ondelete='CASCADE',
            ),
            nullable=False,
        ),
        sa.Column(
            'publication_id',
            sa.BigInteger(),
            sa.ForeignKey(
                'publications.id',
                ondelete='CASCADE',
            ),
            nullable=False,
        ),
        sa.Column(
            'channel',
            sa.String(20),
            nullable=False,
            server_default='TELEGRAM',
        ),
        sa.Column(
            'status',
            sa.String(20),
            nullable=False,
            server_default='PENDING',
        ),
        sa.Column(
            'message',
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            'attempts',
            sa.Integer(),
            nullable=False,
            server_default='0',
        ),
        sa.Column(
            'last_error',
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            'sent_at',
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.UniqueConstraint(
            'vulnerability_id',
            'channel',
            name='uq_notifications_vulnerability_channel',
        ),
    )

    op.create_index(
        'idx_notifications_status',
        'notifications',
        ['status'],
    )


def downgrade() -> None:
    op.drop_index(
        'idx_notifications_status',
        table_name='notifications',
    )
    op.drop_table('notifications')