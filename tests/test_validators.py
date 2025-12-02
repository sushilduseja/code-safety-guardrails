from src.validators.sql_injection import validate_sql_injection
from src.validators.command_execution import validate_command_execution
from src.validators.secrets_scanner import validate_secrets
from src.validators.malicious_imports import validate_malicious_imports
from src.guardrails_config import run_validators


def test_sql_injection_safe():
    code = "SELECT * FROM users WHERE id = :id"  # parameterized style
    result = validate_sql_injection(code)
    assert result["passed"]


def test_sql_injection_unsafe_concat():
    code = 'SELECT * FROM users WHERE name = "' + " + user_input + " + '"'  # concatenation
    result = validate_sql_injection(code)
    assert not result["passed"]
    assert any("string concatenation" in issue.lower() for issue in result["issues"])


def test_command_execution_detects_os_system():
    code = "import os\nos.system('ls')"
    result = validate_command_execution(code)
    assert not result["passed"]


def test_secrets_scanner_redacts():
    code = "AWS_KEY = 'AKIA1234567890ABCDEF'"
    result = validate_secrets(code)
    assert not result["passed"]
    assert "AKIA1234567890ABCDEF" not in result["sanitized_code"]


def test_malicious_imports_detects_socket():
    code = "import socket"
    result = validate_malicious_imports(code)
    assert not result["passed"]
    assert any("socket" in issue for issue in result["issues"])

def test_malicious_imports_detects_dynamic_import():
    code = "__import__('os').system('ls')"
    result = validate_malicious_imports(code)
    assert not result["passed"]
    assert any("Dynamic import" in issue for issue in result["issues"])


def test_command_execution_shell_true():
    code = "subprocess.run(['ls'], shell=True)"
    result = validate_command_execution(code)
    assert not result["passed"]
    assert any("shell=True" in issue for issue in result["issues"])


def test_secrets_github_token():
    code = "TOKEN = 'ghp_" + "a" * 36 + "'"
    result = validate_secrets(code)
    assert not result["passed"]


def test_run_validators_integration():
    # Test safe code passes all validators
    safe_code = "def add(a, b):\n    return a + b"
    result = run_validators(safe_code)
    assert result["passed"] is True
    assert result["sanitized_code"] == safe_code

    # Test unsafe code fails appropriately
    unsafe_code = "import os\nos.system('rm -rf /')"
    result = run_validators(unsafe_code)
    assert result["passed"] is False
    assert result["report"]["command_execution"]["passed"] is False
    assert result["report"]["malicious_imports"]["passed"] is False
    assert len(result["report"]["malicious_imports"]["issues"]) > 0
