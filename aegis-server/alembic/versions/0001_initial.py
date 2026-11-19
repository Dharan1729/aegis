"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-08-08

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_configs",
        sa.Column("tenant_id", sa.String(), primary_key=True),
        sa.Column("jwks_uri_human", sa.String(), nullable=False),
        sa.Column("jwks_uri_service", sa.String(), nullable=False),
    )
    op.create_table(
        "tenant_policies",
        sa.Column("tenant_id", sa.String(), primary_key=True),
        sa.Column("policy_script", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "audit_ledger",
        sa.Column("evaluation_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("human_id", sa.String(), nullable=True),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("resource_urn", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("matched_policy", sa.String(), nullable=True),
        sa.Column("policy_version", sa.String(), nullable=True),
        sa.Column("evaluation_reason", sa.Text(), nullable=False),
    )
    op.create_index("ix_audit_ledger_timestamp", "audit_ledger", ["timestamp"])
    op.create_index("ix_audit_ledger_tenant_id", "audit_ledger", ["tenant_id"])


def downgrade() -> None:
    op.drop_table("audit_ledger")
    op.drop_table("tenant_policies")
    op.drop_table("tenant_configs")
