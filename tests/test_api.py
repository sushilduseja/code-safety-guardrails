"""API-level regression tests for request handling and pipeline behavior."""

import asyncio
from types import SimpleNamespace

import httpx

import src.main as main_module
from src.pipeline import PipelineResult


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


def test_generate_fails_closed_when_validation_raises(monkeypatch):
    monkeypatch.setattr(
        main_module,
        "get_groq_client",
        lambda: StubGroqClient("import socket"),
    )
    def fake_get_pipeline(*args, **kwargs):
        return SimpleNamespace(
            validate=lambda code: (_ for _ in ()).throw(RuntimeError("validator exploded"))
        )
    monkeypatch.setattr(main_module, "get_pipeline", fake_get_pipeline)

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


def test_generate_returns_validator_specific_failures(monkeypatch):
    from src.pipeline import ValidationIssue
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
    monkeypatch.setattr(
        main_module,
        "get_groq_client",
        lambda: StubGroqClient("import os\nos.system('ls')"),
    )
    monkeypatch.setattr(
        main_module,
        "get_pipeline",
        lambda strict=False: SimpleNamespace(validate=lambda code: validation, validators=[SimpleNamespace(name="t")]),
    )

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


def test_generate_rejects_unsupported_language():
    response = request_json(
        "POST",
        "/generate",
        json={"prompt": "write code", "language": "javascript", "strict": False},
    )

    assert response.status_code == 422


def test_root_serves_demo_index():
    response = request_json("GET", "/")

    assert response.status_code == 200
    assert "Code Safety Guardrails" in response.text

