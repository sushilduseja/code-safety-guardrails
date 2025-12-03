"""SQL Injection detection via Guardrails validator."""

import re
from typing import Any, Dict, Optional

from guardrails.validators import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)


@register_validator(name="code/sql_injection", data_type="string")
class SQLInjectionValidator(Validator):
    """Detects SQL injection vulnerabilities in generated code."""

    UNSAFE_PATTERNS = [
        (re.compile(r'f["\'`].*(?:SELECT|INSERT|UPDATE|DELETE).*\{.*\}', re.I | re.S), "f-string SQL"),
        (re.compile(r'SELECT.+["\']\\s*\\+\\s*\\w+\\s*\\+\\s*["\']', re.I | re.S), "string concatenation"),
        (re.compile(r'\.format\s*\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', re.I | re.S), ".format() SQL"),
        (re.compile(r'execute\s*\(\s*["\'].*%s', re.I), "unsafe execute format"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(
        self, value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Check for unsafe SQL patterns."""
        issues = []

        for pattern, desc in self.UNSAFE_PATTERNS:
            if pattern.search(value):
                issues.append(f"Unsafe pattern: {desc}")

        if issues:
            safe_code = self._generate_safe_version(value)
            return FailResult(
                error_message=f"SQL injection risk: {'; '.join(issues)}",
                fix_value=safe_code
            )
        return PassResult()

    def _generate_safe_version(self, code: str) -> str:
        """Convert unsafe SQL to parameterized queries."""
        code = re.sub(
            r'f"SELECT \* FROM (\w+) WHERE (\w+) = \{(\w+)\}"',
            r'"SELECT * FROM \1 WHERE \2 = ?"  # Use parameterized query with (\3,)',
            code
        )
        return code + "\n# SECURITY: Use parameterized queries to prevent SQL injection"
