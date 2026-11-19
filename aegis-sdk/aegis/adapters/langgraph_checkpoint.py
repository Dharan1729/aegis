"""Stale-authorization detection for LangGraph checkpoints.

A long-running graph can be checkpointed (paused) and resumed hours or
days later. If the tenant's policy changed in between — someone tightened
access after the graph paused — resuming under the old, looser
understanding of what's allowed is a real gap: the graph's own tool-call
gate (`SecureToolNode`) only re-checks at the moment each tool runs, but
nothing currently stops a resumed run from reaching that point using
stale assumptions baked into its checkpointed state.

`GovernedCheckpointer` wraps any `BaseCheckpointSaver`: on save, it stamps
the *current* policy version into the checkpoint's metadata; on load, it
compares that stamp against the tenant's *live* policy version (a cheap
call to `GET /v1/policy-version/{tenant_id}`, not a full evaluate()) and
raises `StaleAuthorizationError` if they differ, so the host has to
handle the mismatch explicitly rather than silently resuming under a
policy that's no longer current.
"""

from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    BaseCheckpointSaver,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
)

from aegis.client import AegisClient

_VERSION_KEY = "aegis_policy_version"


class StaleAuthorizationError(Exception):
    """Raised on checkpoint resume when the tenant's policy has changed
    since this checkpoint was saved."""


class GovernedCheckpointer(BaseCheckpointSaver):
    def __init__(self, wrapped: BaseCheckpointSaver, aegis_client: AegisClient, tenant_id: str) -> None:
        self._wrapped = wrapped
        self._aegis_client = aegis_client
        self._tenant_id = tenant_id

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: Any,
    ) -> RunnableConfig:
        stamped = {**metadata, _VERSION_KEY: self._aegis_client.policy_version(self._tenant_id)}
        return self._wrapped.put(config, checkpoint, stamped, new_versions)

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: Any,
    ) -> RunnableConfig:
        stamped = {**metadata, _VERSION_KEY: await self._aegis_client.apolicy_version(self._tenant_id)}
        return await self._wrapped.aput(config, checkpoint, stamped, new_versions)

    def _check_staleness(self, tup: CheckpointTuple | None, live_version: str) -> None:
        if tup is None:
            return
        saved_version = tup.metadata.get(_VERSION_KEY) if tup.metadata else None
        if saved_version is not None and saved_version != live_version:
            raise StaleAuthorizationError(
                f"tenant '{self._tenant_id}' policy changed since this checkpoint was saved "
                f"(saved under version {saved_version}, current is {live_version}) — "
                "resuming would run under stale authorization assumptions"
            )

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        tup = self._wrapped.get_tuple(config)
        self._check_staleness(tup, self._aegis_client.policy_version(self._tenant_id))
        return tup

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        tup = await self._wrapped.aget_tuple(config)
        self._check_staleness(tup, await self._aegis_client.apolicy_version(self._tenant_id))
        return tup

    def list(self, config: RunnableConfig | None, **kwargs: Any):
        # A host resuming from checkpoint *history* (get_state_history /
        # list) rather than the latest checkpoint (get_tuple) is a common
        # LangGraph pattern — this must be checked too, or resuming from
        # an older point in history silently skips the staleness check
        # this whole wrapper exists to enforce.
        live_version = self._aegis_client.policy_version(self._tenant_id)
        for tup in self._wrapped.list(config, **kwargs):
            self._check_staleness(tup, live_version)
            yield tup

    async def alist(self, config: RunnableConfig | None, **kwargs: Any):
        live_version = await self._aegis_client.apolicy_version(self._tenant_id)
        async for tup in self._wrapped.alist(config, **kwargs):
            self._check_staleness(tup, live_version)
            yield tup

    def put_writes(self, config: RunnableConfig, writes: Any, task_id: str, task_path: str = "") -> None:
        return self._wrapped.put_writes(config, writes, task_id, task_path)

    async def aput_writes(
        self, config: RunnableConfig, writes: Any, task_id: str, task_path: str = ""
    ) -> None:
        return await self._wrapped.aput_writes(config, writes, task_id, task_path)
