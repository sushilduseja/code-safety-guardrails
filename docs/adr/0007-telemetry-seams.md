# ADR-0007: Telemetry behind two seams (AuditAdapter + MetricsAdapter)

**Status:** Accepted

**Date:** 2026-06-14

## Context

Audit logging and metric recording were procedural module-level functions in `main.py` (`_log_audit`, `record_metric`) with no seam. Tests that exercised `generate()` caused real SQLite writes and metric state mutations — side effects that couldn't be isolated.

## Decision

Introduce two separate seams:

1. **`AuditAdapter`** — records audit log entries (SQLite in production, null in tests)
2. **`MetricsAdapter`** — records operational metrics (Prometheus-format in production, null in tests)

A higher-level `Telemetry` module wraps both adapters and owns the latency timing via an `async with telemetry.timed():` context manager pattern. The caller is freed from measuring time.

## Consequences

- **Positive:** Tests inject `NullAuditAdapter` / `NullMetricsAdapter` — no SQLite writes, no metric state leakage between test runs.
- **Positive:** Audit format changes affect one adapter, not main.py.
- **Positive:** Timing logic concentrates in Telemetry rather than spreading across finally blocks.
- **Neutral:** Two seams instead of one means more files, but each adapter has a single responsibility.

## Related

- ADR-0005 (Fails-closed) — preserved. Telemetry failures never affect the response.
