# Contributing

Issues and pull requests are welcome. For anything larger than a fix, open an issue first so we can agree on the approach.

## Ground rules

- **Fail closed.** Any new code path that can raise during a decision must end in a DENY, and should have a test that proves it.
- **Measure, don't assert.** A performance or security claim in the docs needs a script in `benchmarks/` and a committed result in `results/`.
- **Keep the adapters thin.** Behaviour shared by every framework (failure handling, masking) belongs in `aegis-sdk/aegis/core.py`, not in one adapter.
- **Report what didn't work.** If a change makes a number worse, say so in the PR and in `docs/benchmarks.md`.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e "aegis-server[test]" -e "aegis-sdk[langgraph,crewai,semantic-kernel,openai-agents,mcp,test]" -e aegis-cli asyncpg
python scripts/gen_test_keys.py
docker compose up --build -d
```

Rust work needs a stable toolchain, or run cargo through Docker:

```bash
docker run --rm -v "$PWD/cedar-sidecar":/src -w /src rust:1-slim cargo test --locked
```

## Tests

| Suite | Needs | Command |
|---|---|---|
| cedar-sidecar | Rust | `cd cedar-sidecar && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` |
| aegis-server unit | nothing | `cd aegis-server && python -m pytest tests/unit` |
| aegis-server integration | the compose stack | `cd aegis-server && python -m pytest tests/integration` |
| aegis-sdk | nothing (framework tests skip if the framework is not installed) | `cd aegis-sdk && python -m pytest tests` |
| end to end | the compose stack | `python scripts/seed_tenant.py && python scripts/smoke_test.py && python examples/quickstart.py` |
| attacks, faults | the compose stack | `AEGIS_RESULTS_DIR=out python -m benchmarks.attacks` and `... benchmarks.fail_closed` |

Lint and format (CI pins ruff 0.16.3):

```bash
ruff check . && ruff format --check .
for p in aegis-server aegis-sdk aegis-cli; do (cd $p && ruff check . && ruff format --check .); done
```

If ports 5432, 6380, 8000 or 9000 are taken, move the stack with the `AEGIS_*_PORT` variables in `docker-compose.yml` and point the tests at it with `AEGIS_URL`, `AEGIS_DSN` and `AEGIS_REDIS_URL`.

## Database changes

Add an Alembic migration in `aegis-server/alembic/versions/` (next number, with a `downgrade`). New columns on existing tables need a server default or must be nullable.

## Commits and pull requests

Short imperative subject lines ("Merge annotations strictly in cedar-sidecar"). One concern per PR. CI must pass: lint, Rust, unit, SDK per framework, the integration job (which runs the attack suite and fault injection), and the image scans.
