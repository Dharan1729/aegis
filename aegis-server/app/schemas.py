from typing import Any

from pydantic import BaseModel, Field


class ExecutionPrincipal(BaseModel):
    session_id: str
    workflow_id: str


class ResourceDescriptor(BaseModel):
    type: str
    urn: str


class EvaluateRequest(BaseModel):
    execution_principal: ExecutionPrincipal
    action: str
    resource: ResourceDescriptor
    context: dict[str, Any] = Field(default_factory=dict)


class ExecutionPolicy(BaseModel):
    allowed_tools: list[str] = Field(default_factory=list)
    mask_fields: list[str] = Field(default_factory=list)
    approval_required: bool = False
    # Read from the matched policy's @risk_tier annotation ("low" skips
    # escalation even when approval_required is set — see main.py).
    risk_tier: str | None = None
    # Who/what actually granted approval for this decision: a resolver's
    # `approver` field, "auto (low risk)" for the risk-tier skip, or None
    # when approval wasn't required at all.
    approved_by: str | None = None


class EvaluateResponse(BaseModel):
    decision: str
    correlation_id: str
    latency_ms: float
    execution_policy: ExecutionPolicy | None = None
    graceful_rejection_message: str | None = None
