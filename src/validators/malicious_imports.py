"""Malicious imports detection via Guardrails validator."""

import ast
from typing import Any, Dict, List, Optional

from guardrails.validators import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)


@register_validator(name="code/malicious_imports", data_type="string")
class MaliciousImportsValidator(Validator):
    """Detects dangerous imports via AST analysis."""

    BLOCKED_MODULES = {
        "pickle": "Arbitrary code execution via deserialization",
        "marshal": "Low-level serialization",
        "shelve": "Uses pickle internally",
        "ctypes": "Low-level memory access",
    }

    RESTRICTED_MODULES = {
        "socket": "Network access",
        "requests": "HTTP client",
        "urllib": "URL handling",
        "ftplib": "FTP access",
        "smtplib": "Email capability",
    }

    def __init__(self, strict: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.strict = strict

    def validate(
        self, value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Detect blacklisted and network imports."""
        try:
            tree = ast.parse(value)
        except SyntaxError:
            return PassResult()  # Non-Python passes

        issues = []
        imports_found = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split('.')[0]
                    imports_found.append(module)

            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split('.')[0]
                imports_found.append(module)
                for alias in node.names:
                    if alias.name == "__import__":
                        issues.append("Dynamic __import__() detected")

            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                    issues.append("Dynamic __import__() call detected")

        for mod in imports_found:
            if mod in self.BLOCKED_MODULES:
                issues.append(f"Blocked: {mod}")
            elif self.strict and mod in self.RESTRICTED_MODULES:
                issues.append(f"Restricted (strict): {mod}")

        if issues:
            return FailResult(
                error_message=f"Import security issues: {'; '.join(issues)}"
            )

        return PassResult()
