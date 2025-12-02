from typing import Any, Dict

from src.validators.sql_injection import validate_sql_injection
from src.validators.command_execution import validate_command_execution
from src.validators.secrets_scanner import validate_secrets
from src.validators.malicious_imports import validate_malicious_imports


def run_validators(code: str) -> Dict[str, Any]:
    """Run all custom validators and aggregate results.

    This function does not call Guard.validate() directly; instead it
    mirrors the configured validators in Python for easier testing and
    richer reporting. You can wire Guard.validate() here later if you
    want Guardrails to do additional checks.
    """

    sql_result = validate_sql_injection(code)
    cmd_result = validate_command_execution(code)
    secrets_result = validate_secrets(code)
    imports_result = validate_malicious_imports(code)

    passed = (
        sql_result["passed"]
        and cmd_result["passed"]
        and imports_result["passed"]
        # secrets_result may auto-fix; treat presence of secrets as non-fatal
    )

    sanitized_code = secrets_result.get("sanitized_code", code)

    report: Dict[str, Any] = {
        "sql_injection": sql_result,
        "command_execution": cmd_result,
        "secrets": secrets_result,
        "malicious_imports": imports_result,
        "passed": passed,
    }

    return {"sanitized_code": sanitized_code, "report": report, "passed": passed}
