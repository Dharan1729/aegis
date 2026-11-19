import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit_hash import chain_hash
from app.config import settings
from app.models import AuditChainHead, AuditLedger


async def record_decision(
    session: AsyncSession,
    *,
    tenant_id: str,
    human_id: str | None,
    agent_id: str | None,
    action: str,
    resource_urn: str,
    decision: str,
    matched_policy: str | None,
    policy_version: str | None,
    evaluation_reason: str,
) -> None:
    # Get-or-create this tenant's chain-head row, then lock it for the
    # rest of this transaction so two concurrent aegis-server replicas
    # writing for the *same* tenant can't both read the same "previous
    # hash" and fork the chain. Different tenants' rows are independent,
    # so this never contends across tenants — only within one.
    await session.execute(
        pg_insert(AuditChainHead)
        .values(tenant_id=tenant_id, last_hash=None)
        .on_conflict_do_nothing(index_elements=["tenant_id"])
    )
    head = (
        await session.execute(
            select(AuditChainHead).where(AuditChainHead.tenant_id == tenant_id).with_for_update()
        )
    ).scalar_one()

    evaluation_id = uuid.uuid4()
    timestamp = datetime.now(UTC)
    new_hash = chain_hash(
        secret=settings.audit_chain_hmac_secret,
        evaluation_id=evaluation_id,
        timestamp=timestamp,
        tenant_id=tenant_id,
        human_id=human_id,
        agent_id=agent_id,
        action=action,
        resource_urn=resource_urn,
        decision=decision,
        matched_policy=matched_policy,
        policy_version=policy_version,
        evaluation_reason=evaluation_reason,
        previous_hash=head.last_hash,
    )

    session.add(
        AuditLedger(
            evaluation_id=evaluation_id,
            timestamp=timestamp,
            tenant_id=tenant_id,
            human_id=human_id,
            agent_id=agent_id,
            action=action,
            resource_urn=resource_urn,
            decision=decision,
            matched_policy=matched_policy,
            policy_version=policy_version,
            evaluation_reason=evaluation_reason,
            previous_hash=head.last_hash,
            hash=new_hash,
        )
    )
    head.last_hash = new_hash
    await session.commit()
