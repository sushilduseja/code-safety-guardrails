"""Regression tests for the static demo UI contract."""

from pathlib import Path


DEMO_UI = Path("index.html").read_text(encoding="utf-8")


def test_demo_ui_has_api_env_support():
    assert "VITE_API_URL" in DEMO_UI or "import.meta.env" in DEMO_UI


def test_demo_ui_handles_errors():
    assert "res.ok" in DEMO_UI
    assert "Error:" in DEMO_UI


def test_demo_ui_has_strict_mode():
    assert 'id="strict"' in DEMO_UI
    assert "strict" in DEMO_UI


def test_demo_ui_has_examples():
    assert "Prime checker" in DEMO_UI
    assert "Merge lists" in DEMO_UI
