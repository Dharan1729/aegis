from aegis.client import AegisClient, EvaluateResult, ExecutionPolicy

FIXED_CTX_KWARGS = {
    "tenant_id": "acme",
    "human_token": "h",
    "service_token": "s",
    "session_id": "s1",
    "workflow_id": "w1",
}

EMPLOYEE = {"name": "Ada", "ssn": "123-45-6789", "team": {"lead": "Grace", "SSN": "987-65-4321"}}


class FakeAegisClient(AegisClient):
    """The same decisions for every adapter's tests:

    - `forbidden_tool` is denied;
    - `masked_tool` and `text_tool` are allowed with `ssn` to be masked;
    - the tool named in `raise_for` simulates an aegis-server outage;
    - everything else is allowed.
    """

    def __init__(self, raise_for: str | None = None):
        super().__init__(base_url="http://unused")
        self.raise_for = raise_for
        self.calls: list[dict] = []

    def _decide(self, kwargs):
        self.calls.append(kwargs)
        urn = kwargs["resource_urn"]
        if self.raise_for and urn == f"urn:tool:{self.raise_for}":
            raise ConnectionError("simulated aegis-server outage")
        if urn == "urn:tool:forbidden_tool":
            return EvaluateResult(
                decision="DENY",
                correlation_id="eval_test",
                latency_ms=1.0,
                graceful_rejection_message="Access Denied: policy blocked this tool.",
            )
        masked = urn in ("urn:tool:masked_tool", "urn:tool:text_tool")
        return EvaluateResult(
            decision="ALLOW",
            correlation_id="eval_test",
            latency_ms=1.0,
            execution_policy=ExecutionPolicy(mask_fields=["ssn"] if masked else []),
        )

    def evaluate(self, **kwargs):
        return self._decide(kwargs)

    async def aevaluate(self, **kwargs):
        return self._decide(kwargs)
