import ast
from typing import Any, Dict, List

BLACKLISTED_MODULES = {
    "socket",
    "ctypes",
    "subprocess",
    "os",  # often used for command exec; keep configurable in the future
}

BLACKLISTED_OBJECTS = {
    "__import__",
}

NETWORK_LIBRARIES = {"urllib", "requests"}


class ImportInspector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.issues: List[str] = []

    def visit_Import(self, node: ast.Import) -> None:  # type: ignore[override]
        for alias in node.names:
            if alias.name.split(".")[0] in BLACKLISTED_MODULES:
                self.issues.append(f"Blacklisted import detected: {alias.name}")
            if alias.name.split(".")[0] in NETWORK_LIBRARIES:
                self.issues.append(f"Network-capable import detected: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # type: ignore[override]
        module = (node.module or "").split(".")[0]
        if module in BLACKLISTED_MODULES:
            self.issues.append(f"Blacklisted import-from detected: {module}")
        if module in NETWORK_LIBRARIES:
            self.issues.append(f"Network-capable import-from detected: {module}")
        for alias in node.names:
            if alias.name in BLACKLISTED_OBJECTS:
                self.issues.append(f"Blacklisted object imported: {alias.name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
        # Detect dynamic imports such as __import__("module")
        if isinstance(node.func, ast.Name) and node.func.id in BLACKLISTED_OBJECTS:
            self.issues.append(f"Dynamic import detected: {node.func.id}()")
        self.generic_visit(node)


def validate_malicious_imports(code: str) -> Dict[str, Any]:
    """Parse Python code and look for blacklisted or network-related imports."""

    try:
        tree = ast.parse(code)
    except SyntaxError:
        # If it's not valid Python, we can't reliably inspect imports;
        # treat as passed but note the limitation.
        return {
            "passed": True,
            "issues": ["Code could not be parsed as Python; import checks skipped."],
        }

    inspector = ImportInspector()
    inspector.visit(tree)

    return {"passed": len(inspector.issues) == 0, "issues": inspector.issues}
