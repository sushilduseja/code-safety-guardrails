"""Malicious imports detection Validator."""

import ast

class MaliciousImportsValidator:
    """Detects dangerous imports via AST analysis."""
    name = "code/malicious_imports"

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

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(self, code: str) -> tuple[bool, str | None, str | None]:
        """Detect blacklisted and network imports."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, None, f"Code failed to parse: {e}"

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
            # no fix possible for imports unless we strip them
            return False, None, f"Import security issues: {'; '.join(issues)}"

        return True, None, None
