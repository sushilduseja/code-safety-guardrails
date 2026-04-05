"""Command execution detection Validator."""

import ast
import re

class CommandExecutionValidator:
    """Detects dangerous command execution patterns."""
    name = "code/command_execution"

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

    def validate(self, code: str) -> tuple[bool, str | None, str | None]:
        """Check for dangerous execution patterns."""
        issues = []

        # AST-based detection
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_name = self._get_call_name(node)
                    if call_name in self.DANGEROUS_CALLS:
                        issues.append(f"{call_name}: {self.DANGEROUS_CALLS[call_name]}")
        except SyntaxError:
            # Fallback to regex for non-Python code
            for func in self.DANGEROUS_CALLS:
                if re.search(rf'\b{re.escape(func)}\s*\(', code):
                    issues.append(f"{func} detected")

        # Check for shell=True parameter
        if self.SHELL_TRUE_PATTERN.search(code):
            issues.append("shell=True allows shell injection")

        if issues:
            fixed = self._sanitize(code)
            return False, fixed, f"Dangerous execution: {'; '.join(issues)}"

        return True, None, None

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function name from AST Call node."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _sanitize(self, code: str) -> str | None:
        """Apply only conservative fixes that preserve the original call shape."""
        if "os.system" in code:
            return None
        if self.SHELL_TRUE_PATTERN.search(code):
            code = re.sub(r'shell\s*=\s*True', 'shell=False, check=True', code)
            return code + "\n# SECURITY: Disabled shell and enabled check=True"
        return None
