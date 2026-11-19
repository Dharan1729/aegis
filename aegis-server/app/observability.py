import time
from contextlib import contextmanager

from fastapi import FastAPI, Response
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.config import settings

_provider = TracerProvider(resource=Resource.create({"service.name": "aegis-server"}))
if settings.otel_exporter_otlp_endpoint:
    _provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint, insecure=True))
    )
trace.set_tracer_provider(_provider)
tracer = trace.get_tracer("aegis-server")

# Per-stage breakdown of where evaluate() spends its time: one end-to-end
# number cannot tell a Postgres regression from a slow JWKS fetch or Cedar.
STAGE_LATENCY = Histogram(
    "aegis_evaluate_stage_latency_seconds",
    "Latency of each stage inside POST /v1/evaluate",
    ["stage"],
)
DECISIONS = Counter(
    "aegis_evaluate_decisions_total",
    "Count of evaluate() decisions by outcome",
    ["decision"],
)
FAIL_CLOSED = Counter(
    "aegis_evaluate_fail_closed_total",
    "Requests denied because a stage failed, by exception type",
    ["cause"],
)
AUDIT_WRITE_FAILURES = Counter(
    "aegis_audit_write_failures_total",
    "Decisions that could not be written to the audit log (each one was denied)",
)


@contextmanager
def stage(name: str):
    with tracer.start_as_current_span(name):
        start = time.perf_counter()
        try:
            yield
        finally:
            STAGE_LATENCY.labels(stage=name).observe(time.perf_counter() - start)


def instrument_app(app: FastAPI) -> None:
    FastAPIInstrumentor.instrument_app(app)

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
