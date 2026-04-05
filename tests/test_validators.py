"""Unit tests for custom CodeValidator pipeline."""

import pytest
import ast

from src.pipeline import ValidatorPipeline
from src.validators.sql_injection import SQLInjectionValidator
from src.validators.command_execution import CommandExecutionValidator
from src.validators.secrets_scanner import SecretsValidator
from src.validators.malicious_imports import MaliciousImportsValidator
from src.validators.factory import create_code_guard


class TestSQLInjectionValidator:
    """Test SQL injection detection."""

    @pytest.fixture
    def validator(self):
        return SQLInjectionValidator()

    def test_safe_parameterized(self, validator):
        code = "SELECT * FROM users WHERE id = :id"
        passed, fix, msg = validator.validate(code)
        assert passed

    def test_safe_driver_parameterized_query_passes(self, validator):
        code = (
            'cursor.execute("SELECT * FROM users WHERE email = %s", '
            "(email_address,))"
        )
        passed, fix, msg = validator.validate(code)
        assert passed

    def test_detects_fstring_sql(self, validator):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert "SQL injection" in msg

    def test_detects_string_concat(self, validator):
        code = 'query = "SELECT * FROM users WHERE name = \'" + name + "\'"'
        passed, fix, msg = validator.validate(code)
        assert not passed

    def test_provides_executable_fix(self, validator):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert fix is not None
        ast.parse(fix)   # must be valid Python
        assert "?" in fix
        assert "user_id" in fix


class TestCommandExecutionValidator:
    """Test command execution detection."""

    @pytest.fixture
    def validator(self):
        return CommandExecutionValidator()

    def test_detects_os_system(self, validator):
        code = "import os\nos.system('ls')"
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert "os.system" in msg

    def test_detects_eval(self, validator):
        code = "eval(user_input)"
        passed, fix, msg = validator.validate(code)
        assert not passed

    def test_detects_shell_true(self, validator):
        code = "subprocess.run(['ls'], shell=True)"
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert "shell" in msg.lower()

    def test_fixes_shell_true(self, validator):
        code = "subprocess.run(['ls'], shell=True)"
        passed, fix, msg = validator.validate(code)
        assert fix is not None
        assert "shell=False" in fix
        assert "check=True" in fix

    def test_shell_true_fix_does_not_duplicate_check_true(self, validator):
        code = "subprocess.run(['ls'], shell=True, check=True)"
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert fix is not None
        assert fix.count("check=True") == 1

    def test_passes_safe_subprocess(self, validator):
        code = "subprocess.run(['ls'], shell=False, check=True)"
        passed, fix, msg = validator.validate(code)
        assert passed


class TestSecretsValidator:
    """Test secrets detection and redaction."""

    @pytest.fixture
    def validator(self):
        return SecretsValidator()

    def test_detects_aws_key(self, validator):
        code = "AWS_KEY = 'AKIA1234567890ABCDEF'"
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert "AWS" in msg

    def test_redacts_aws_key(self, validator):
        code = "AWS_KEY = 'AKIA1234567890ABCDEF'"
        passed, fix, msg = validator.validate(code)
        assert "AKIA1234567890ABCDEF" not in fix
        assert "****" in fix

    def test_detects_github_token(self, validator):
        code = 'TOKEN = "ghp_' + "a" * 36 + '"'
        passed, fix, msg = validator.validate(code)
        assert not passed

    def test_detects_password(self, validator):
        code = 'password = "super_secret_123"'
        passed, fix, msg = validator.validate(code)
        assert not passed

    def test_redacts_api_key_assignment(self, validator):
        code = 'api_key = "super-secret-key-12345"'
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert 'super-secret-key-12345' not in fix
        assert 'api_key="***"' in fix

    def test_passes_env_var(self, validator):
        code = 'db_pass = os.environ.get("DB_PASSWORD")'
        passed, fix, msg = validator.validate(code)
        assert passed


class TestMaliciousImportsValidator:
    """Test import security detection."""

    @pytest.fixture
    def validator(self):
        return MaliciousImportsValidator(strict=False)

    def test_blocks_pickle(self, validator):
        code = "import pickle\ndata = pickle.loads(input_data)"
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert "pickle" in msg.lower()

    def test_blocks_ctypes(self, validator):
        code = "import ctypes"
        passed, fix, msg = validator.validate(code)
        assert not passed

    def test_detects_dynamic_import(self, validator):
        code = "mod = __import__(user_module)"
        passed, fix, msg = validator.validate(code)
        assert not passed
        assert "__import__" in msg

    def test_strict_mode_blocks_socket(self):
        strict_validator = MaliciousImportsValidator(strict=True)
        code = "import socket"
        passed, fix, msg = strict_validator.validate(code)
        assert not passed

    def test_strict_mode_blocks_requests(self):
        strict_validator = MaliciousImportsValidator(strict=True)
        code = "import requests\nrequests.get('https://example.com')"
        passed, fix, msg = strict_validator.validate(code)
        assert not passed
        assert "requests" in msg

    def test_normal_mode_allows_requests(self, validator):
        code = "import requests\nrequests.get('https://example.com')"
        passed, fix, msg = validator.validate(code)
        assert passed

    def test_normal_allows_json(self, validator):
        code = "import json"
        passed, fix, msg = validator.validate(code)
        assert passed
        
    def test_unparseable_code_fails(self, validator):
        code = "import ("
        passed, fix, msg = validator.validate(code)
        assert not passed


class TestComposedGuard:
    """Test full Guard validation pipeline."""

    def test_safe_code_passes(self):
        pipeline = create_code_guard()
        safe = "def add(a, b):\n    return a + b"
        result = pipeline.validate(safe)
        assert result.passed

    def test_unsafe_code_fails(self):
        pipeline = create_code_guard()
        unsafe = "import os\nos.system('ls')"
        result = pipeline.validate(unsafe)
        assert not result.passed
        assert result.validated_output == ""
        assert any(
            issue.validator == "code/command_execution"
            for issue in result.issues
        )

    def test_secrets_auto_fixed(self):
        pipeline = create_code_guard()
        code_with_secret = "KEY = 'AKIA1234567890ABCDEF'"
        result = pipeline.validate(code_with_secret)
        # In the pipeline, if a validator fails but has a fix, passed becomes False but the code process continues
        # wait, pipeline returns passed=False but output has the redacted key
        assert not result.passed
        assert "AKIA1234567890ABCDEF" not in result.validated_output

    def test_strict_mode_enforced(self):
        pipeline = create_code_guard(strict=True)
        code = "import socket"
        result = pipeline.validate(code)
        assert not result.passed
        assert any(
            issue.validator == "code/malicious_imports"
            for issue in result.issues
        )
