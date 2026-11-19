"""add approval_webhook_hmac_secret to tenant_configs

Signs the approval-webhook request/response round trip so the response
can't be forged by anything able to answer on that URL (a compromised
internal service, MITM on an http:// endpoint) — previously any JSON
body claiming {"approved": true} was trusted outright. See app/approval.py.

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-14

"""

import sqlalchemy as sa

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenant_configs", sa.Column("approval_webhook_hmac_secret", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenant_configs", "approval_webhook_hmac_secret")
