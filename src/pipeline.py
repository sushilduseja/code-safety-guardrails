from dataclasses import dataclass, field
from typing import Protocol

@dataclass
class ValidationIssue:
    validator: str
    message: str
    severity: str = "error"

@dataclass
class PipelineResult:
    passed: bool
    issues: list[ValidationIssue]
    validated_output: str

class CodeValidator(Protocol):
    name: str
    def validate(self, code: str) -> tuple[bool, str | None, str | None]:
        # returns (passed, fix_value_or_none, error_message_or_none)
        ...

class ValidatorPipeline:
    def __init__(self, validators: list[CodeValidator]):
        self.validators = validators

    def validate(self, code: str) -> PipelineResult:
        output = code
        issues = []
        passed = True
        for v in self.validators:
            ok, fix, msg = v.validate(output)
            if not ok:
                passed = False
                issues.append(ValidationIssue(validator=v.name, message=msg or ""))
                if fix is not None:
                    output = fix   # apply and continue; block if no fix
                else:
                    return PipelineResult(passed=False, issues=issues, validated_output="")
        return PipelineResult(passed=passed, issues=issues, validated_output=output)
