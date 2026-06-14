import json
import logging
from typing import Protocol

from src.db import connect

logger = logging.getLogger(__name__)


class AuditAdapter(Protocol):

    async def record(
        self,
        request_id: str,
        tenant_id: str,
        prompt_hash: str,
        language: str,
        strict: bool,
        validators_run_json: str,
        issues_json: str,
        passed: int,
        raw_code_hash: str | None,
        protected_code_hash: str | None,
        latency_ms: int,
    ) -> None: ...


class NullAuditAdapter:

    async def record(
        self,
        request_id: str = "",
        tenant_id: str = "",
        prompt_hash: str = "",
        language: str = "",
        strict: bool = False,
        validators_run_json: str = "",
        issues_json: str = "",
        passed: int = 0,
        raw_code_hash: str | None = None,
        protected_code_hash: str | None = None,
        latency_ms: int = 0,
    ) -> None:
        pass


class SQLiteAuditAdapter:

    async def record(
        self,
        request_id: str,
        tenant_id: str,
        prompt_hash: str,
        language: str,
        strict: bool,
        validators_run_json: str,
        issues_json: str,
        passed: int,
        raw_code_hash: str | None,
        protected_code_hash: str | None,
        latency_ms: int,
    ) -> None:
        try:
            with connect() as conn:
                conn.execute(
                    """INSERT INTO audit_log (
                        request_id, tenant_id, prompt_hash, language, strict,
                        validators_run, issues_found, passed, raw_code_hash, protected_code_hash, latency_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        request_id, tenant_id, prompt_hash, language, strict,
                        validators_run_json, issues_json, passed, raw_code_hash, protected_code_hash, latency_ms
                    )
                )
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)


class MetricsAdapter(Protocol):

    def record(
        self,
        tenant: str,
        passed: bool,
        validators_failed: list[str],
        latency: int,
    ) -> None: ...

    def render(self) -> str: ...


class NullMetricsAdapter:

    def record(
        self,
        tenant: str = "",
        passed: bool = False,
        validators_failed: list[str] | None = None,
        latency: int = 0,
    ) -> None:
        pass

    def render(self) -> str:
        return ""


class PrometheusMetricsAdapter:

    def __init__(self) -> None:
        self._requests_total: dict[tuple[str, bool], int] = {}
        self._validator_failures: dict[str, int] = {}
        self._latency_ms: list[int] = []

    def record(
        self,
        tenant: str,
        passed: bool,
        validators_failed: list[str],
        latency: int,
    ) -> None:
        key = (tenant, passed)
        self._requests_total[key] = self._requests_total.get(key, 0) + 1
        for v in validators_failed:
            self._validator_failures[v] = self._validator_failures.get(v, 0) + 1
        self._latency_ms.append(latency)
        if len(self._latency_ms) > 1000:
            self._latency_ms = self._latency_ms[-1000:]

    def render(self) -> str:
        lines: list[str] = []
        for (tenant, passed), count in self._requests_total.items():
            lines.append(
                f'guardrails_requests_total{{tenant="{tenant}",passed="{str(passed).lower()}"}} {count}'
            )
        for v, count in self._validator_failures.items():
            lines.append(
                f'guardrails_validator_failures_total{{validator="{v}"}} {count}'
            )
        latencies = sorted(self._latency_ms)
        if latencies:
            p50 = latencies[int(len(latencies) * 0.5)]
            p95 = latencies[int(len(latencies) * 0.95)]
            lines.append(f"guardrails_latency_p50_ms {p50}")
            lines.append(f"guardrails_latency_p95_ms {p95}")
        else:
            lines.append("guardrails_latency_p50_ms 0")
            lines.append("guardrails_latency_p95_ms 0")
        return "\n".join(lines) + "\n"


class Telemetry:

    def __init__(
        self,
        audit: AuditAdapter,
        metrics: MetricsAdapter,
    ) -> None:
        self._audit = audit
        self._metrics = metrics

    @property
    def metrics(self) -> MetricsAdapter:
        return self._metrics

    async def record(
        self,
        request_id: str,
        tenant_id: str,
        prompt_hash: str,
        language: str,
        strict: bool,
        validators_run: list[str],
        issues: list[dict],
        passed: bool,
        raw_code_hash: str | None,
        protected_code_hash: str | None,
        latency_ms: int,
    ) -> None:
        validators_run_json = json.dumps(validators_run)
        issues_json = json.dumps(issues)

        await self._audit.record(
            request_id, tenant_id, prompt_hash, language, int(strict),
            validators_run_json, issues_json, int(passed),
            raw_code_hash, protected_code_hash, latency_ms,
        )
        failed_validators = [i["validator"] for i in issues]
        self._metrics.record(tenant_id, passed, failed_validators, latency_ms)
