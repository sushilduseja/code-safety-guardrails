"""Command execution detection via Guardrails validator."""

import ast
import re
from typing import Any, Dict, Optional

from guardrails.validators import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)


@register_validator(name="code/command_execution", data_type="string")
class CommandExecutionValidator(Validator):
    """Detects dangerous command execution patterns."""

    DANGEROUS_CALLS = {
        "os.system": "Arbitrary shell command",
        "os.popen": "Shell command with pipes",
        "subprocess.call": "Process execution (prefer run)",
        "subprocess.Popen": "Low-level process spawning",
        "eval": "Arbitrary code execution",
        "exec": "Arbitrary code execution",
        "compile": "Dynamic code compilation",
    }

    SHELL_TRUE_PATTERN = re.compile(r'shell\s*=\s*True')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(
        self, value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Check for dangerous execution patterns."""
        issues = []

        # AST-based detection
        try:
            tree = ast.parse(value)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_name = self._get_call_name(node)
                    if call_name in self.DANGEROUS_CALLS:
                        issues.append(f"{call_name}: {self.DANGEROUS_CALLS[call_name]}")
        except SyntaxError:
            # Fallback to regex for non-Python code
            for func in self.DANGEROUS_CALLS:
                if re.search(rf'\b{re.escape(func)}\s*\(', value):
                    issues.append(f"{func} detected")

        # Check for shell=True parameter
        if self.SHELL_TRUE_PATTERN.search(value):
            issues.append("shell=True allows shell injection")

        if issues:
            fixed = self._sanitize(value)
            return FailResult(
                error_message=f"Dangerous execution: {'; '.join(issues)}",
                fix_value=fixed
            )

        return PassResult()

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function name from AST Call node."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _sanitize(self, code: str) -> str:
        """Apply security fixes."""
        code = re.sub(r'shell\s*=\s*True', 'shell=False, check=True', code)
        code = re.sub(
            r'\bos\.system\s*\(([^)]+)\)',
            r'subprocess.run([\1], shell=False, check=True)',
            code
        )
        return code + "\n# SECURITY: Disabled shell and enabled check=True"
