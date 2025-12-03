"""Factory for creating configured Guardrails Guard with all validators."""

from guardrails import Guard, OnFailAction

from src.validators.sql_injection import SQLInjectionValidator
from src.validators.command_execution import CommandExecutionValidator
from src.validators.secrets_scanner import SecretsValidator
from src.validators.malicious_imports import MaliciousImportsValidator


def create_code_guard(strict: bool = False) -> Guard:
    """
    Create a Guard instance with all security validators.

    Args:
        strict: Enable strict import blocking

    Returns:
        Configured Guard instance
    """
    guard = Guard(name="code_security")

    guard.use(SQLInjectionValidator(on_fail=OnFailAction.FIX))
    guard.use(CommandExecutionValidator(on_fail=OnFailAction.FIX))
    guard.use(SecretsValidator(on_fail=OnFailAction.FIX))
    guard.use(
        MaliciousImportsValidator(
            strict=strict,
            on_fail=OnFailAction.EXCEPTION if strict else OnFailAction.FIX,
        )
    )

    return guard
