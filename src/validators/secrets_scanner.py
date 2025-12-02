import re
from typing import Any, Dict, List

AWS_ACCESS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
GITHUB_TOKEN_PATTERN = re.compile(r"ghp_[a-zA-Z0-9]{36}")
HARDCODED_PASSWORD_PATTERN = re.compile(
    r"password\s*=\s*(['\"])[^\1]+\1", re.IGNORECASE
)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")


def _redact_secrets(code: str) -> str:
    """Naively redact detected secrets by replacing with ***.

    This is a best-effort sanitizer for demo purposes.
    """

    redacted = AWS_ACCESS_KEY_PATTERN.sub("AKIA****************", code)
    redacted = GITHUB_TOKEN_PATTERN.sub("ghp_********************************", redacted)
    redacted = HARDCODED_PASSWORD_PATTERN.sub("password = \"***\"", redacted)
    redacted = PRIVATE_KEY_PATTERN.sub("-----BEGIN PRIVATE KEY-----", redacted)
    return redacted


def validate_secrets(code: str) -> Dict[str, Any]:
    """Scan for likely secrets and attempt redaction.

    Returns dict with `passed`, `issues`, and `sanitized_code`.
    """

    issues: List[str] = []

    if AWS_ACCESS_KEY_PATTERN.search(code):
        issues.append("Possible AWS access key detected.")
    if GITHUB_TOKEN_PATTERN.search(code):
        issues.append("Possible GitHub token detected.")
    if HARDCODED_PASSWORD_PATTERN.search(code):
        issues.append("Possible hardcoded password detected.")
    if PRIVATE_KEY_PATTERN.search(code):
        issues.append("Private key material detected.")

    sanitized_code = _redact_secrets(code) if issues else code

    return {"passed": len(issues) == 0, "issues": issues, "sanitized_code": sanitized_code}
