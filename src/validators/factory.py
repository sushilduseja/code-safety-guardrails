from src.pipeline import ValidatorPipeline
from src.validators.sql_injection import SQLInjectionValidator
from src.validators.command_execution import CommandExecutionValidator
from src.validators.secrets_scanner import SecretsValidator
from src.validators.malicious_imports import MaliciousImportsValidator

def create_code_guard(strict: bool = False) -> ValidatorPipeline:
    validators = [
        SQLInjectionValidator(),
        CommandExecutionValidator(),
        SecretsValidator(),
        MaliciousImportsValidator(strict=strict),
    ]

    return ValidatorPipeline(validators=validators)


