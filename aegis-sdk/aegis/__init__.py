"""Aegis SDK: authorize AI agent tool calls against Cedar policy."""

from aegis.client import AegisClient, EvaluateResult, ExecutionPolicy
from aegis.core import AegisContext, Guard, ResourceDescriptor, Verdict, default_resource_resolver
from aegis.masking import MASK, mask

__version__ = "0.2.0"

__all__ = [
    "MASK",
    "AegisClient",
    "AegisContext",
    "EvaluateResult",
    "ExecutionPolicy",
    "Guard",
    "ResourceDescriptor",
    "Verdict",
    "default_resource_resolver",
    "mask",
]
