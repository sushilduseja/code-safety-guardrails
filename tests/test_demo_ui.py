"""Regression tests for the static demo UI contract."""

from pathlib import Path


DEMO_UI = Path("index.html").read_text(encoding="utf-8")


def test_demo_ui_has_api_env_support():
    assert "VITE_API_URL" in DEMO_UI or "window.ENV" in DEMO_UI


def test_demo_ui_handles_errors():
    assert "res.ok" in DEMO_UI
    assert "Error:" in DEMO_UI


def test_demo_ui_has_strict_mode():
    assert 'id="strict"' in DEMO_UI
    assert "strict" in DEMO_UI


def test_demo_ui_has_examples():
    assert "/examples" in DEMO_UI
    assert "loadExamples" in DEMO_UI


def test_demo_ui_renders_examples_without_innerhtml_prompt_injection():
    assert "renderExampleButtons" in DEMO_UI
    assert "button.dataset.prompt = item.prompt" in DEMO_UI
    assert "button.textContent = item.label" in DEMO_UI


def test_demo_ui_supports_larger_example_sets():
    assert 'id="safeExamples"' in DEMO_UI
    assert 'id="securityExamples"' in DEMO_UI
    assert "flex-wrap: wrap;" in DEMO_UI


def test_demo_ui_does_not_fallback_to_raw_code_for_blocked_protected_output():
    assert "function getProtectedOutput(data)" in DEMO_UI
    assert "return '// Blocked: no safe rewrite available';" in DEMO_UI
    assert "data.protected_code || data.code" not in DEMO_UI
