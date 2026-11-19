"""rekey audit_chain_head per-tenant instead of a single global row

A single global chain-head row serialized every tenant's audit writes
onto one lock (a real contention bottleneck) and coupled every tenant's
chain into one shared sequence. Rekeying by tenant_id fixes both.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-10

"""

import sqlalchemy as sa

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("audit_chain_head")
    op.create_table(
        "audit_chain_head",
        sa.Column("tenant_id", sa.String(), primary_key=True),
        sa.Column("last_hash", sa.String(), nullable=True),
    )
    # Seed a fresh chain-head for every existing tenant so none of them
    # hit a missing-row case on their next audit write. app/audit.py's
    # get-or-create-on-write also covers any tenant added after this
    # migration runs, so this is a convenience backfill, not a hard
    # dependency.
    op.execute(
        "INSERT INTO audit_chain_head (tenant_id, last_hash) "
        "SELECT tenant_id, NULL FROM tenant_configs "
        "ON CONFLICT (tenant_id) DO NOTHING"
    )


def downgrade() -> None:
    op.drop_table("audit_chain_head")
    op.create_table(
        "audit_chain_head",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_hash", sa.String(), nullable=True),
    )
    op.execute("INSERT INTO audit_chain_head (id, last_hash) VALUES (1, NULL)")
