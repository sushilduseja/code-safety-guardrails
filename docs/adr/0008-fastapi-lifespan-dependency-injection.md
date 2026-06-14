# ADR-0008: FastAPI lifespan + per-dependency Depends() for seam injection

**Status:** Accepted

**Date:** 2026-06-14

## Context

Dependencies were scattered as module-level globals in `main.py` (`_groq_client`, `_metrics`) with lazy init functions (`get_groq_client()`). Tests monkey-patched these globals because there was no explicit injection path.

## Decision

Use FastAPI's `lifespan` context manager to construct all dependencies at startup, store them in `app.state`, and expose via per-dependency `Depends()` functions in a dedicated `src/deps.py` module.

Dependencies constructed at startup:
- `CodeGenerator` — `DemoCodeGenerator(registry, RealCodeGenerator(groq_client))`
- `Telemetry` — wraps `SQLiteAuditAdapter` + `PrometheusMetricsAdapter`
- `get_pipeline` — remains a stateless function call (no startup cost)

Test modules construct their own `app.state` with null/test adapters — no monkey-patching.

## Consequences

- **Positive:** Dependency graph is visible in one place (the lifespan block).
- **Positive:** Tests inject adapters through the same seam production uses — `Depends()` is the one true injection point.
- **Positive:** No module-level mutable state survives across test runs.
- **Neutral:** One more file (`src/deps.py`).
