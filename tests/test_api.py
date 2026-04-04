"""API-level regression tests for request handling and guard behavior."""

import asyncio
from types import SimpleNamespace

import httpx

import src.main as main_module


class StubGroqClient:
    """Simple async stub for API tests."""

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


def test_get_guard_caches_per_strict_mode(monkeypatch):
    calls = []

    def fake_create_code_guard(strict: bool = False):
        calls.append(strict)
        return {"strict": strict}

    monkeypatch.setattr(main_module, "create_code_guard", fake_create_code_guard)
    main_module._guards.clear()

    relaxed = main_module.get_guard(False)
    strict = main_module.get_guard(True)
    relaxed_again = main_module.get_guard(False)

    assert relaxed["strict"] is False
    assert strict["strict"] is True
    assert relaxed_again is relaxed
    assert calls == [False, True]


def test_generate_requires_api_key_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("CODE_SAFETY_API_KEY", raising=False)

    response = request_json(
        "POST",
        "/generate",
        json={"prompt": "write code", "language": "python", "strict": False},
    )

    assert response.status_code == 503


def test_generate_fails_closed_when_validation_raises(monkeypatch):
    monkeypatch.setattr(
        main_module,
        "get_groq_client",
        lambda: StubGroqClient("import socket"),
    )
    monkeypatch.setattr(
        main_module,
        "get_guard",
        lambda strict=False: SimpleNamespace(
            validate=lambda code: (_ for _ in ()).throw(RuntimeError("validator exploded"))
        ),
    )

    response = request_json(
        "POST",
        "/generate",
        json={"prompt": "write code", "language": "python", "strict": True},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["passed"] is False
    assert body["code"] == ""
    assert body["raw_code"] is None
    assert body["issues"][0]["validator"] == "guard"


def test_generate_returns_validator_specific_failures(monkeypatch):
    validation = SimpleNamespace(
        validated_output="import os\nos.system('ls')",
        validation_passed=False,
        validation_summaries=[
            SimpleNamespace(
                validator_name="CommandExecutionValidator",
                validator_status="fail",
                failure_reason="Dangerous execution: os.system: Arbitrary shell command",
            )
        ],
    )
    monkeypatch.setattr(
        main_module,
        "get_groq_client",
        lambda: StubGroqClient("import os\nos.system('ls')"),
    )
    monkeypatch.setattr(
        main_module,
        "get_guard",
        lambda strict=False: SimpleNamespace(validate=lambda code: validation),
    )

    response = request_json(
        "POST",
        "/generate",
        json={"prompt": "write code", "language": "python", "strict": False},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["passed"] is False
    assert body["issues"] == [
        {
            "validator": "CommandExecutionValidator",
            "message": "Dangerous execution: os.system: Arbitrary shell command",
            "severity": "error",
        }
    ]


def test_generate_rejects_unsupported_language():
    response = request_json(
        "POST",
        "/generate",
        json={"prompt": "write code", "language": "javascript", "strict": False},
    )

    assert response.status_code == 422


def test_health_reports_boolean_api_key_status():
    response = request_json("GET", "/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert isinstance(body["api_key_configured"], bool)
    assert isinstance(body["auth_required"], bool)
    assert isinstance(body["rate_limit_per_minute"], int)


def test_examples_endpoint_returns_safe_and_security_test_prompts():
    response = request_json("GET", "/examples")

    assert response.status_code == 200
    body = response.json()
    assert "safe" in body
    assert "security_test" in body
    assert len(body["safe"]) == 4
    assert len(body["security_test"]) == 4
    assert any("prime" in e["prompt"].lower() for e in body["safe"])
    assert any("shell=True" in e["prompt"] or "pickle" in e["prompt"] for e in body["security_test"])


def test_root_serves_demo_index():
    response = request_json("GET", "/")

    assert response.status_code == 200
    assert "Code Safety Guardrails" in response.text


def test_generate_requires_api_key_when_configured(monkeypatch):
    monkeypatch.setenv("CODE_SAFETY_API_KEY", "secret")

    response = request_json(
        "POST",
        "/generate",
        json={"prompt": "write code", "language": "python", "strict": False},
    )

    assert response.status_code == 401


def test_generate_accepts_valid_api_key(monkeypatch):
    monkeypatch.setenv("CODE_SAFETY_API_KEY", "secret")
    monkeypatch.setattr(
        main_module,
        "get_groq_client",
        lambda: StubGroqClient("def add(a, b):\n    return a + b"),
    )
    monkeypatch.setattr(
        main_module,
        "get_guard",
        lambda strict=False: SimpleNamespace(
            validate=lambda code: SimpleNamespace(
                validated_output=code,
                validation_passed=True,
                validation_logs=[],
            )
        ),
    )

    response = request_json(
        "POST",
        "/generate",
        headers={"X-API-Key": "secret"},
        json={"prompt": "write code", "language": "python", "strict": False},
    )

    assert response.status_code == 200
    assert response.json()["passed"] is True


def test_generate_rate_limits_requests(monkeypatch):
    main_module._rate_limit_buckets.clear()
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1")
    monkeypatch.setenv("CODE_SAFETY_API_KEY", "secret")
    monkeypatch.setattr(
        main_module,
        "get_groq_client",
        lambda: StubGroqClient("def add(a, b):\n    return a + b"),
    )
    monkeypatch.setattr(
        main_module,
        "get_guard",
        lambda strict=False: SimpleNamespace(
            validate=lambda code: SimpleNamespace(
                validated_output=code,
                validation_passed=True,
                validation_logs=[],
            )
        ),
    )

    first = request_json(
        "POST",
        "/generate",
        headers={"X-API-Key": "secret"},
        json={"prompt": "write code", "language": "python", "strict": False},
    )
    second = request_json(
        "POST",
        "/generate",
        headers={"X-API-Key": "secret"},
        json={"prompt": "write code", "language": "python", "strict": False},
    )

    assert first.status_code == 200
    assert second.status_code == 429
