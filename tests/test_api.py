"""API-level regression tests for request handling and pipeline behavior."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import httpx

import src.main as main_module
from src.deps import get_code_generator
from src.pipeline import PipelineResult


class StubGroqClient:
    """Lightweight GroqClient-compatible stub for API tests.
    Has the same generate_code interface as the real GroqClient."""

    def __init__(self, code: str) -> None:
        self.code = code

    async def generate_code(self, prompt: str, language: str) -> str:
        return self.code


def request_json(method: str, path: str, **kwargs):
    async def _request():
        transport = httpx.ASGITransport(app=main_module.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            response = await client.request(method, path, **kwargs)
            return response

    return asyncio.run(_request())


def load_registry() -> dict[str, str]:
    p = Path("config/demo_registry.json")
    return json.loads(p.read_text()).get("prompts", {}) if p.exists() else {}


def setup_default_state():
    """Set up app.state with DemoCodeGenerator + null telemetry."""
    from src.telemetry import Telemetry, NullAuditAdapter, NullMetricsAdapter
    from src.generator import DemoCodeGenerator

    main_module.app.state.code_generator = DemoCodeGenerator(load_registry(), None)
    main_module.app.state.telemetry = Telemetry(NullAuditAdapter(), NullMetricsAdapter())
    main_module.app.dependency_overrides = {}


def clear_overrides():
    main_module.app.dependency_overrides = {}


def test_generate_fails_closed_when_validation_raises():
    from src.generator import RealCodeGenerator
    from src.telemetry import Telemetry, NullAuditAdapter, NullMetricsAdapter

    main_module.app.state.telemetry = Telemetry(NullAuditAdapter(), NullMetricsAdapter())

    stub = StubGroqClient("import socket")
    main_module.app.dependency_overrides[get_code_generator] = lambda: RealCodeGenerator(stub)  # type: ignore[arg-type]

    def fake_get_pipeline(*args, **kwargs):
        return SimpleNamespace(
            validate=lambda code: (_ for _ in ()).throw(RuntimeError("validator exploded"))
        )

    import src.main as mm
    monkey_original = mm.get_pipeline
    mm.get_pipeline = fake_get_pipeline
    try:
        response = request_json(
            "POST",
            "/generate",
            json={"prompt": "write code", "language": "python", "strict": True},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["passed"] is False
        assert body["code"] == "import socket"
        assert body["protected_code"] == ""
        assert body["issues"][0]["validator"] == "pipeline"
    finally:
        mm.get_pipeline = monkey_original
        clear_overrides()


def test_generate_returns_validator_specific_failures():
    from src.generator import RealCodeGenerator
    from src.pipeline import ValidationIssue
    from src.telemetry import Telemetry, NullAuditAdapter, NullMetricsAdapter

    main_module.app.state.telemetry = Telemetry(NullAuditAdapter(), NullMetricsAdapter())

    stub = StubGroqClient("import os\nos.system('ls')")
    main_module.app.dependency_overrides[get_code_generator] = lambda: RealCodeGenerator(stub)  # type: ignore[arg-type]

    validation = PipelineResult(
        validated_output="",
        passed=False,
        issues=[
            ValidationIssue(
                validator="code/command_execution",
                message="Dangerous execution: os.system: Arbitrary shell command",
                severity="error",
            )
        ],
    )

    import src.main as mm
    monkey_original = mm.get_pipeline
    mm.get_pipeline = lambda strict=False: SimpleNamespace(validate=lambda code: validation, validators=[SimpleNamespace(name="t")])
    try:
        response = request_json(
            "POST",
            "/generate",
            json={"prompt": "write code", "language": "python", "strict": False},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["passed"] is False
        assert body["protected_code"] == ""
        assert body["issues"] == [
            {
                "validator": "code/command_execution",
                "message": "Dangerous execution: os.system: Arbitrary shell command",
                "severity": "error",
            }
        ]
    finally:
        mm.get_pipeline = monkey_original
        clear_overrides()


def test_generate_rejects_unsupported_language():
    setup_default_state()
    try:
        response = request_json(
            "POST",
            "/generate",
            json={"prompt": "write code", "language": "javascript", "strict": False},
        )

        assert response.status_code == 422
    finally:
        clear_overrides()


def test_root_serves_demo_index():
    response = request_json("GET", "/")

    assert response.status_code == 200
    assert "Code Safety Guardrails" in response.text


def test_examples_endpoint_includes_corner_case_demos():
    response = request_json("GET", "/examples")

    assert response.status_code == 200
    body = response.json()

    safe_labels = {item["label"] for item in body["safe"]}
    security_labels = {item["label"] for item in body["security_test"]}

    assert "Factorial edge case" in safe_labels
    assert "os.system (blocked)" in security_labels
    assert "API key (redacted)" in security_labels
    assert "requests (strict blocked)" in security_labels


def test_generate_uses_deterministic_shell_demo_rewrite():
    setup_default_state()
    try:
        response = request_json(
            "POST",
            "/generate",
            json={"prompt": "subprocess.run(['ls', '-la'], shell=True, check=True)", "language": "python", "strict": False},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["raw_code"] == "import subprocess\nsubprocess.run(['ls', '-la'], shell=True, check=True)"
        assert "shell=False" in body["protected_code"]
        assert body["issues"][0]["validator"] == "code/command_execution"
    finally:
        clear_overrides()


def test_generate_uses_deterministic_sql_demo_rewrite():
    setup_default_state()
    try:
        response = request_json(
            "POST",
            "/generate",
            json={"prompt": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")', "language": "python", "strict": False},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["raw_code"] == 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        assert body["protected_code"] == "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        assert body["issues"][0]["validator"] == "code/sql_injection"
    finally:
        clear_overrides()


def test_generate_uses_deterministic_blocked_strict_demo():
    setup_default_state()
    try:
        response = request_json(
            "POST",
            "/generate",
            json={"prompt": "import requests\nrequests.get('https://example.com', timeout=5)", "language": "python", "strict": True},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["raw_code"] == "import requests\nrequests.get('https://example.com', timeout=5)"
        assert body["protected_code"] == ""
        assert body["passed"] is False
        assert body["issues"][0]["validator"] == "code/malicious_imports"
    finally:
        clear_overrides()


def test_generate_strips_markdown_fences_before_validation():
    from src.generator import RealCodeGenerator
    from src.telemetry import Telemetry, NullAuditAdapter, NullMetricsAdapter

    main_module.app.state.telemetry = Telemetry(NullAuditAdapter(), NullMetricsAdapter())

    stub = StubGroqClient("```python\ndef is_prime(n):\n    return n > 1\n```")
    main_module.app.dependency_overrides[get_code_generator] = lambda: RealCodeGenerator(stub)  # type: ignore[arg-type]

    import src.main as mm
    monkey_original_pipeline = mm.get_pipeline
    mm.get_pipeline = lambda strict=False: SimpleNamespace(
        validate=lambda code: PipelineResult(passed=True, issues=[], validated_output=code),
        validators=[SimpleNamespace(name="test")],
    )
    try:
        response = request_json(
            "POST",
            "/generate",
            json={"prompt": "write code", "language": "python", "strict": True},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["passed"] is True
        assert body["raw_code"] == "def is_prime(n):\n    return n > 1"
        assert body["protected_code"] == "def is_prime(n):\n    return n > 1"
        assert body["issues"] == []
    finally:
        mm.get_pipeline = monkey_original_pipeline
        clear_overrides()
