"""Factory for creating configured code safety pipeline with all validators."""

from src.pipeline import ValidatorPipeline
from src.validators.sql_injection import SQLInjectionValidator
from src.validators.command_execution import CommandExecutionValidator
from src.validators.secrets_scanner import SecretsValidator
from src.validators.malicious_imports import MaliciousImportsValidator

def create_code_guard(strict: bool = False) -> ValidatorPipeline:
    """
    Create a ValidatorPipeline instance with all security validators.

    Args:
        strict: Enable strict import blocking

    Returns:
        Configured ValidatorPipeline instance
    """
    validators = [
        SQLInjectionValidator(),
        CommandExecutionValidator(),
        SecretsValidator(),
        MaliciousImportsValidator(strict=strict),
    ]

    return ValidatorPipeline(validators=validators)

def get_pipeline(strict: bool = False) -> ValidatorPipeline:
    return create_code_guard(strict)
