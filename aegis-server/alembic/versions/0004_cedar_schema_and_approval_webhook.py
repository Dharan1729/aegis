"""add cedar_schema and approval_webhook_url to tenant_configs

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-08

"""

import sqlalchemy as sa

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenant_configs", sa.Column("cedar_schema", sa.Text(), nullable=True))
    op.add_column("tenant_configs", sa.Column("approval_webhook_url", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenant_configs", "approval_webhook_url")
    op.drop_column("tenant_configs", "cedar_schema")
