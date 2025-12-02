import re
from typing import Any, Dict, List

COMMAND_PATTERNS = [
    re.compile(r"os\.system\s*\(", re.MULTILINE),
    re.compile(r"subprocess\.", re.MULTILINE),
    re.compile(r"eval\s*\(", re.MULTILINE),
    re.compile(r"exec\s*\(", re.MULTILINE),
    re.compile(r"pickle\.", re.MULTILINE),
    re.compile(r"marshal\.", re.MULTILINE),
]

SHELL_TRUE_PATTERN = re.compile(r"shell\s*=\s*True", re.MULTILINE)


def validate_command_execution(code: str) -> Dict[str, Any]:
    """Detect potentially dangerous command execution primitives in code."""

    issues: List[str] = []

    for pattern in COMMAND_PATTERNS:
        if pattern.search(code):
            issues.append(f"Disallowed pattern detected: {pattern.pattern}")

    if SHELL_TRUE_PATTERN.search(code):
        issues.append("Use of shell=True detected in subprocess call.")

    return {"passed": len(issues) == 0, "issues": issues}
