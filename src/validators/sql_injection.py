"""SQL Injection detection Validator."""

import re
import ast

class _SQLRewriter(ast.NodeTransformer):
    """Rewrites f-string SQL inside cursor.execute() calls to parameterized form."""

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        # target: cursor.execute(f"SELECT ... {var} ...", ...)
        if not self._is_execute_call(node):
            return node
        if not node.args:
            return node
        first_arg = node.args[0]
        if not isinstance(first_arg, ast.JoinedStr):  # f-string
            return node
        template, params = self._extract_fstring(first_arg)
        if not params:
            return node
        # Replace f-string with plain string using ? placeholders
        node.args[0] = ast.Constant(value=template)
        param_tuple = ast.Tuple(elts=[ast.Name(id=p, ctx=ast.Load()) for p in params], ctx=ast.Load())
        if len(node.args) == 1:
            node.args.append(param_tuple)
        return node

    def _is_execute_call(self, node):
        return (isinstance(node.func, ast.Attribute) and node.func.attr == "execute")

    def _extract_fstring(self, node):
        parts, params = [], []
        for part in node.values:
            if isinstance(part, ast.Constant):
                parts.append(part.value)
            elif isinstance(part, ast.FormattedValue):
                parts.append("?")
                if isinstance(part.value, ast.Name):
                    params.append(part.value.id)
        return "".join(parts), params

def rewrite_sql(code: str) -> str | None:
    try:
        tree = ast.parse(code)
        new_tree = _SQLRewriter().visit(tree)
        ast.fix_missing_locations(new_tree)
        return ast.unparse(new_tree)
    except Exception:
        return None

class SQLInjectionValidator:
    """Detects SQL injection vulnerabilities in generated code."""
    name = "code/sql_injection"

    UNSAFE_PATTERNS = [
        (
            re.compile(r'f["\'`].*(?:SELECT|INSERT|UPDATE|DELETE).*\{.*\}', re.I | re.S),
            "f-string SQL",
        ),
        (
            re.compile(r'SELECT.+["\']\s*\+\s*\w+\s*\+\s*["\']', re.I | re.S),
            "string concatenation",
        ),
        (
            re.compile(r'\.format\s*\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', re.I | re.S),
            ".format() SQL",
        ),
    ]

    def validate(self, code: str) -> tuple[bool, str | None, str | None]:
        """Check for unsafe SQL patterns."""
        issues = []

        for pattern, desc in self.UNSAFE_PATTERNS:
            if pattern.search(code):
                issues.append(f"Unsafe pattern: {desc}")

        if issues:
            safe_code = rewrite_sql(code)
            return False, safe_code, f"SQL injection risk: {'; '.join(issues)}"
        return True, None, None
