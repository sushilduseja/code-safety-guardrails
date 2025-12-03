"""FastAPI application with Guardrails Guard.validate() integration."""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.gemini_client import GeminiClient
from src.validators.factory import create_code_guard


class GenerateRequest(BaseModel):
    """Request model for code generation."""

    prompt: str = Field(..., description="User prompt describing the desired code")
    language: str = Field("python", description="Target programming language")
    strict: bool = Field(False, description="Strict validation mode")


class ValidationIssue(BaseModel):
    """Single validation issue."""

    validator: str
    message: str
    severity: str


class GenerateResponse(BaseModel):
    """Response model for code generation."""

    code: str
    passed: bool
    issues: List[ValidationIssue]
    raw_code: Optional[str] = None


app = FastAPI(title="Code Safety Guardrails", version="1.0.0")
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception as e:
    print(f"Warning: Could not mount static files: {e}")

_gemini_client: Optional[GeminiClient] = None
_guard: Optional[Any] = None


def get_gemini_client() -> GeminiClient:
    """Lazily initialize Gemini client only when needed."""
    global _gemini_client
    if _gemini_client is None:
        _gemini_client = GeminiClient()
    return _gemini_client


def get_guard(strict: bool = False) -> Any:
    """Lazily initialize Guard only when needed."""
    global _guard
    if _guard is None:
        _guard = create_code_guard(strict=strict)
    return _guard


@app.get("/health")
async def health() -> Dict[str, str]:
    """Health check endpoint."""
    has_api_key = "GOOGLE_API_KEY" in os.environ
    return {"status": "ok", "api_key_configured": has_api_key}


@app.post("/generate", response_model=GenerateResponse)
async def generate(req: GenerateRequest) -> GenerateResponse:
    """Generate and validate code through Guardrails Guard.validate()."""
    try:
        gemini_client = get_gemini_client()
        raw_code = await gemini_client.generate_code(req.prompt, req.language.lower())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    # Get guard with appropriate strict mode
    try:
        guard = get_guard(strict=req.strict)
        validation = guard.validate(raw_code)
        validated_code = validation.validated_output or raw_code
        passed = validation.validation_passed
    except Exception as e:
        # If Guard validation fails, return raw code with error
        return GenerateResponse(
            code=raw_code,
            passed=False,
            issues=[
                ValidationIssue(
                    validator="guard",
                    message=f"Validation error: {str(e)}",
                    severity="error",
                )
            ],
            raw_code=raw_code,
        )

    # Extract validation results from logs
    issues = []
    if hasattr(validation, "validation_logs"):
        for log in validation.validation_logs:
            if hasattr(log, "validation_result"):
                result = log.validation_result
                if hasattr(result, "outcome") and result.outcome == "fail":
                    validator_name = getattr(log, "validator_name", "unknown")
                    error_msg = getattr(result, "error_message", "Validation failed")
                    issues.append(
                        ValidationIssue(
                            validator=validator_name,
                            message=error_msg,
                            severity="error",
                        )
                    )

    return GenerateResponse(
        code=validated_code,
        passed=passed,
        issues=issues,
        raw_code=raw_code if not passed else None,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)