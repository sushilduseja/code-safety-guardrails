"""Secrets detection and redaction via Guardrails validator."""

import re
from typing import Any, Dict, Optional

from guardrails.validators import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)


@register_validator(name="code/secrets_exposure", data_type="string")
class SecretsValidator(Validator):
    """Detects and auto-redacts hardcoded secrets."""

    SECRET_PATTERNS = {
        r'AKIA[0-9A-Z]{16}': ("AWS Access Key", "AKIA****"),
        r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}': ("GitHub Token", "gh*_****"),
        r'sk-[a-zA-Z0-9]{32,}': ("OpenAI Key", "sk-****"),
        r'xox[baprs]-[a-zA-Z0-9-]+': ("Slack Token", "xox*-****"),
        r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----': ("Private Key", "[REDACTED]"),
        r'(?i)(?:password|passwd)\s*=\s*["\'][^"\']{4,}["\']': ("Hardcoded Password", 'password="***"'),
        r'(?i)(?:api_key|apikey)\s*=\s*["\'][^"\']{8,}["\']': ("API Key", 'api_key="***"'),
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(
        self, value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Detect secrets and provide redacted version."""
        issues = []
        redacted = value

        for pattern, (desc, replacement) in self.SECRET_PATTERNS.items():
            if re.search(pattern, value):
                issues.append(desc)
                redacted = re.sub(pattern, replacement, redacted)

        if issues:
            return FailResult(
                error_message=f"Secrets detected: {', '.join(issues)}",
                fix_value=redacted
            )

        return PassResult()
