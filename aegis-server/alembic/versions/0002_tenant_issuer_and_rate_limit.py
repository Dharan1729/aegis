"""add tenant issuer cross-check + rate limit columns

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-08

"""

import sqlalchemy as sa

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenant_configs", sa.Column("expected_issuer_human", sa.String(), nullable=True))
    op.add_column("tenant_configs", sa.Column("expected_issuer_service", sa.String(), nullable=True))
    op.add_column("tenant_configs", sa.Column("rate_limit_per_minute", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenant_configs", "rate_limit_per_minute")
    op.drop_column("tenant_configs", "expected_issuer_service")
    op.drop_column("tenant_configs", "expected_issuer_human")
