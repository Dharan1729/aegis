"""add tenant_policy_history

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-08

"""

import sqlalchemy as sa

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_policy_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("policy_script", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tenant_policy_history_tenant_id", "tenant_policy_history", ["tenant_id"])


def downgrade() -> None:
    op.drop_table("tenant_policy_history")
