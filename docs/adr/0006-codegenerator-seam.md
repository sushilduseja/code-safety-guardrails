# ADR-0006: CodeGenerator seam with DemoCodeGenerator wrapping RealCodeGenerator

**Status:** Accepted

**Date:** 2026-06-14

## Context

The demo bypass logic (`DETERMINISTIC_DEMO_CODE` dict + inline check) lived inside the FastAPI `generate()` endpoint. This meant:
- The HTTP handler knew about two concerns (request handling + demo routing)
- Tests monkey-patched `get_groq_client()` to inject a stub
- Adding new demo prompts required editing `main.py`

## Decision

Introduce a `CodeGenerator` protocol seam with two primary adapters:

1. **`RealCodeGenerator`** — calls Groq API, normalizes output
2. **`DemoCodeGenerator`** — checks a configurable registry for canned code; falls back to a wrapped `CodeGenerator` for unmatched prompts

The endpoint constructs one `CodeGenerator` (demo wrapping real) and calls `generate()` once. Tests inject whichever adapter they need through the seam.

A third adapter, `StubGroqClient`, continues to exist in tests for cases that need arbitrary code injection without touching the registry.

The registry is loaded from an external file (`demo_registry.json`) to decouple demo data from generator code.

## Consequences

- **Positive:** Demo routing logic concentrates in one adapter. Adding demo prompts requires only editing the JSON file. The endpoint's interface shrinks to calling `generator.generate()`.
- **Positive:** Tests no longer monkey-patch — they inject the appropriate adapter through the seam.
- **Neutral:** The `DemoCodeGenerator` always carries a reference to a fallback `CodeGenerator`. This is invisible to the endpoint.

## Related

- ADR-0002 (Deterministic demo mode) — superseded in implementation, but the intent (reliable demo behavior) is preserved.
