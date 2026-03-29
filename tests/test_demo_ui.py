"""Regression tests for the static demo UI contract."""

from pathlib import Path


DEMO_UI = Path("static/demo_ui.html").read_text(encoding="utf-8")


def test_demo_ui_accepts_optional_api_key():
    assert 'id="api-key"' in DEMO_UI
    assert '"X-API-Key"' in DEMO_UI


def test_demo_ui_handles_http_errors_explicitly():
    assert "if (!response.ok)" in DEMO_UI
    assert "Request Failed (" in DEMO_UI
