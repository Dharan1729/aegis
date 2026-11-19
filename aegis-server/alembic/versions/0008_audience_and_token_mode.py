"""add optional audience checks and a per-tenant single-use token switch

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-19

"""

import sqlalchemy as sa

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenant_configs", sa.Column("expected_audience_human", sa.String(), nullable=True))
    op.add_column("tenant_configs", sa.Column("expected_audience_service", sa.String(), nullable=True))
    op.add_column(
        "tenant_configs",
        sa.Column("single_use_tokens", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    op.drop_column("tenant_configs", "single_use_tokens")
    op.drop_column("tenant_configs", "expected_audience_service")
    op.drop_column("tenant_configs", "expected_audience_human")
