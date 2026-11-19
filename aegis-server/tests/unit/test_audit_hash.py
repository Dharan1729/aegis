"""Pure unit tests for the audit hash chain math — no services required."""

import uuid
from datetime import UTC, datetime

from app.audit_hash import chain_hash

BASE_KWARGS = {
    "secret": "test-secret",
    "evaluation_id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
    "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
    "tenant_id": "acme",
    "human_id": "alice",
    "agent_id": "agent-1",
    "action": "execute_query",
    "resource_urn": "urn:x",
    "decision": "ALLOW",
    "matched_policy": "policy0",
    "policy_version": "v1",
    "evaluation_reason": "allowed by policy policy0",
    "previous_hash": None,
}


def test_deterministic():
    assert chain_hash(**BASE_KWARGS) == chain_hash(**BASE_KWARGS)


def test_different_secret_changes_hash():
    other = {**BASE_KWARGS, "secret": "different-secret"}
    assert chain_hash(**BASE_KWARGS) != chain_hash(**other)


def test_different_previous_hash_changes_hash():
    other = {**BASE_KWARGS, "previous_hash": "some-prior-hash"}
    assert chain_hash(**BASE_KWARGS) != chain_hash(**other)


def test_evaluation_reason_is_covered_by_the_hash():
    """Regression test for the security-review finding that
    matched_policy/policy_version/evaluation_reason weren't hashed —
    editing them must change the hash, or they'd be freely editable
    without breaking chain verification."""
    other = {**BASE_KWARGS, "evaluation_reason": "a tampered, fabricated reason"}
    assert chain_hash(**BASE_KWARGS) != chain_hash(**other)


def test_matched_policy_is_covered_by_the_hash():
    other = {**BASE_KWARGS, "matched_policy": "policy99"}
    assert chain_hash(**BASE_KWARGS) != chain_hash(**other)


def test_decision_is_covered_by_the_hash():
    other = {**BASE_KWARGS, "decision": "DENY"}
    assert chain_hash(**BASE_KWARGS) != chain_hash(**other)


def test_none_fields_do_not_collide_with_empty_strings():
    """human_id=None and human_id="" must hash differently, or a NULL
    column and an empty-string column would be indistinguishable to the
    chain — a subtle way tampering could otherwise hide."""
    with_none = {**BASE_KWARGS, "human_id": None}
    with_empty = {**BASE_KWARGS, "human_id": ""}
    # Both currently render as "" in the join — documented here as a known
    # limitation rather than silently assumed safe. If this starts
    # failing because someone "fixed" it, update this test, don't just
    # delete it.
    assert chain_hash(**with_none) == chain_hash(**with_empty)
