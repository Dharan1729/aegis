import asyncio

from aegis.core import AegisContext, Guard, ResourceDescriptor
from aegis.masking import MASK
from tests.conftest import EMPLOYEE, FIXED_CTX_KWARGS, FakeAegisClient

CTX = AegisContext(**FIXED_CTX_KWARGS)


def test_allow_carries_mask_fields():
    v = Guard(FakeAegisClient()).check(CTX, "masked_tool")
    assert v.allowed and v.mask_fields == ["ssn"]


def test_deny_carries_the_server_message():
    v = Guard(FakeAegisClient()).check(CTX, "forbidden_tool")
    assert not v.allowed and v.message == "Access Denied: policy blocked this tool."


def test_client_outage_is_a_denial_not_an_exception():
    v = Guard(FakeAegisClient(raise_for="any_tool")).check(CTX, "any_tool")
    assert not v.allowed and "unable to verify" in v.message


def test_failing_context_provider_is_a_denial():
    def boom():
        raise KeyError("no identity")

    v = Guard(FakeAegisClient()).check(boom, "any_tool")
    assert not v.allowed and "KeyError" in v.message


def test_async_check_fails_closed_too():
    v = asyncio.run(Guard(FakeAegisClient(raise_for="any_tool")).acheck(CTX, "any_tool"))
    assert not v.allowed


def test_resource_resolver_and_arguments_reach_the_request():
    client = FakeAegisClient()
    Guard(client).check(
        CTX, "sql", {"table": "payroll"}, lambda n, a: ResourceDescriptor("table", a["table"])
    )
    assert client.calls[-1]["resource_urn"] == "payroll"
    assert client.calls[-1]["action"] == "sql"
    assert client.calls[-1]["context"] == {"tool_name": "sql"}


def test_finish_masks_structured_output():
    guard = Guard(FakeAegisClient())
    out = guard.finish(guard.check(CTX, "masked_tool"), EMPLOYEE)
    assert out["ssn"] == MASK


def test_finish_withholds_unmaskable_output_by_default():
    guard = Guard(FakeAegisClient())
    out = guard.finish(guard.check(CTX, "text_tool"), "SSN 123-45-6789")
    assert "Access Denied" in out and "123-45-6789" not in out


def test_finish_can_pass_unmaskable_output_when_told_to():
    guard = Guard(FakeAegisClient(), on_unmaskable="allow")
    assert guard.finish(guard.check(CTX, "text_tool"), "SSN 1") == "SSN 1"
