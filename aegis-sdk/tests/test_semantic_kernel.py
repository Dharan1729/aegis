import pytest

sk = pytest.importorskip("semantic_kernel")

import asyncio

from semantic_kernel import Kernel
from semantic_kernel.filters import FilterTypes
from semantic_kernel.functions import KernelArguments, kernel_function

from aegis.adapters.semantic_kernel import AegisContext, make_aegis_function_filter
from aegis.masking import MASK
from tests.conftest import EMPLOYEE, FIXED_CTX_KWARGS, FakeAegisClient

CTX = AegisContext(**FIXED_CTX_KWARGS)


class DemoPlugin:
    @kernel_function(name="allowed_tool", description="An allowed tool.")
    def allowed_tool(self, x: int) -> str:
        return f"allowed_tool result: {x}"

    @kernel_function(name="masked_tool", description="Returns a record with a masked field.")
    def masked_tool(self, x: int) -> dict:
        return EMPLOYEE

    @kernel_function(name="forbidden_tool", description="A forbidden tool.")
    def forbidden_tool(self, x: int) -> str:
        return f"forbidden_tool result: {x}"


def _build_kernel(aegis_client):
    kernel = Kernel()
    kernel.add_plugin(DemoPlugin(), plugin_name="demo")
    kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, make_aegis_function_filter(aegis_client))
    return kernel


def test_allowed_function_executes():
    kernel = _build_kernel(FakeAegisClient())
    fn = kernel.get_function("demo", "allowed_tool")
    result = asyncio.run(kernel.invoke(fn, KernelArguments(x=1, aegis_context=CTX)))
    assert "allowed_tool result" in str(result)


def test_forbidden_function_returns_graceful_denial():
    kernel = _build_kernel(FakeAegisClient())
    fn = kernel.get_function("demo", "forbidden_tool")
    result = asyncio.run(kernel.invoke(fn, KernelArguments(x=1, aegis_context=CTX)))
    assert "Access Denied" in str(result)


def test_missing_aegis_context_denies_instead_of_running():
    kernel = _build_kernel(FakeAegisClient())
    fn = kernel.get_function("demo", "allowed_tool")
    result = asyncio.run(kernel.invoke(fn, KernelArguments(x=1)))
    assert "Access Denied" in str(result) and "allowed_tool result" not in str(result)


def test_output_is_masked():
    kernel = _build_kernel(FakeAegisClient())
    fn = kernel.get_function("demo", "masked_tool")
    result = asyncio.run(kernel.invoke(fn, KernelArguments(x=1, aegis_context=CTX)))
    assert result.value["ssn"] == MASK


def test_aegis_outage_denies():
    kernel = _build_kernel(FakeAegisClient(raise_for="allowed_tool"))
    fn = kernel.get_function("demo", "allowed_tool")
    result = asyncio.run(kernel.invoke(fn, KernelArguments(x=1, aegis_context=CTX)))
    assert "Access Denied" in str(result)
