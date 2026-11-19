"""hash-chained audit log

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-08

"""

import sqlalchemy as sa

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_ledger", sa.Column("previous_hash", sa.String(), nullable=True))
    # Non-nullable in the model, but existing rows (if any) predate the
    # chain and have no computable hash — backfill with a sentinel so the
    # column can be added without breaking existing data, then tighten.
    op.add_column("audit_ledger", sa.Column("hash", sa.String(), nullable=True))
    op.execute("UPDATE audit_ledger SET hash = 'pre-chain' WHERE hash IS NULL")
    op.alter_column("audit_ledger", "hash", nullable=False)

    op.create_table(
        "audit_chain_head",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_hash", sa.String(), nullable=True),
    )
    op.execute("INSERT INTO audit_chain_head (id, last_hash) VALUES (1, NULL)")


def downgrade() -> None:
    op.drop_table("audit_chain_head")
    op.drop_column("audit_ledger", "hash")
    op.drop_column("audit_ledger", "previous_hash")
