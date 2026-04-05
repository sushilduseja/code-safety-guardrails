"""Secrets detection and redaction Validator."""

import re

class SecretsValidator:
    """Detects and auto-redacts hardcoded secrets."""
    name = "code/secrets_exposure"

    SECRET_PATTERNS = {
        r'AKIA[0-9A-Z]{16}': ("AWS Access Key", "AKIA****"),
        r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}': ("GitHub Token", "gh*_****"),
        r'sk-[a-zA-Z0-9]{32,}': ("OpenAI Key", "sk-****"),
        r'xox[baprs]-[a-zA-Z0-9-]+': ("Slack Token", "xox*-****"),
        r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----': ("Private Key", "[REDACTED]"),
        r'(?i)(?:password|passwd)\s*=\s*["\'][^"\']{4,}["\']': ("Hardcoded Password", 'password="***"'),
        r'(?i)(?:api_key|apikey)\s*=\s*["\'][^"\']{8,}["\']': ("API Key", 'api_key="***"'),
    }

    def validate(self, code: str) -> tuple[bool, str | None, str | None]:
        """Detect secrets and provide redacted version."""
        issues = []
        redacted = code

        for pattern, (desc, replacement) in self.SECRET_PATTERNS.items():
            if re.search(pattern, code):
                issues.append(desc)
                redacted = re.sub(pattern, replacement, redacted)

        if issues:
            return False, redacted, f"Secrets detected: {', '.join(issues)}"

        return True, None, None
