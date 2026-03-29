"""FastAPI application with Guardrails Guard.validate() integration."""

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.gemini_client import GeminiClient
from src.validators.factory import create_code_guard


# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


logger = logging.getLogger(__name__)
RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RATE_LIMIT = 30
_rate_limit_buckets: Dict[str, List[float]] = {}


class GenerateRequest(BaseModel):
    """Request model for code generation."""

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="User prompt describing the desired code",
    )
    language: Literal["python"] = Field(
        "python",
        description="Target programming language",
    )
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
    logger.warning("Could not mount static files: %s", e)

_gemini_client: Optional[GeminiClient] = None
_guards: Dict[bool, Any] = {}


def get_gemini_client() -> GeminiClient:
    """Lazily initialize Gemini client only when needed."""
    global _gemini_client
    if _gemini_client is None:
        _gemini_client = GeminiClient()
    return _gemini_client


def get_guard(strict: bool = False) -> Any:
    """Lazily initialize Guard only when needed."""
    guard = _guards.get(strict)
    if guard is None:
        guard = create_code_guard(strict=strict)
        _guards[strict] = guard
    return guard


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Optionally enforce a simple shared API key for external access."""
    environment = os.getenv("ENVIRONMENT", "development").lower()
    configured_api_key = os.getenv("CODE_SAFETY_API_KEY")
    if environment not in {"development", "test"} and not configured_api_key:
        raise HTTPException(status_code=503, detail="Service is missing CODE_SAFETY_API_KEY")
    if configured_api_key and x_api_key != configured_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


def enforce_rate_limit(request: Request) -> None:
    """Apply a simple per-client sliding-window rate limit to Gemini-backed calls."""
    environment = os.getenv("ENVIRONMENT", "development").lower()
    if environment == "test":
        return

    limit = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", str(DEFAULT_RATE_LIMIT)))
    if limit <= 0:
        return

    client_host = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    bucket = [ts for ts in _rate_limit_buckets.get(client_host, []) if ts >= window_start]
    if len(bucket) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)
    _rate_limit_buckets[client_host] = bucket


def extract_validation_issues(validation: Any) -> List[ValidationIssue]:
    """Convert Guardrails validator logs into stable API response issues."""
    issues: List[ValidationIssue] = []
    for log in getattr(validation, "validation_logs", []):
        result = getattr(log, "validation_result", None)
        if getattr(result, "outcome", None) != "fail":
            continue
        issues.append(
            ValidationIssue(
                validator=getattr(log, "validator_name", "unknown"),
                message=getattr(result, "error_message", "Validation failed"),
                severity="error",
            )
        )
    return issues


@app.get("/health")
async def health() -> Dict[str, bool | str | int]:
    """Health check endpoint."""
    has_api_key = "GOOGLE_API_KEY" in os.environ
    has_auth_key = "CODE_SAFETY_API_KEY" in os.environ
    return {
        "status": "ok",
        "api_key_configured": has_api_key,
        "auth_required": has_auth_key,
        "rate_limit_per_minute": int(
            os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", str(DEFAULT_RATE_LIMIT))
        ),
    }


@app.post("/generate", response_model=GenerateResponse)
async def generate(
    request: Request,
    req: GenerateRequest,
    _api_key: None = Depends(require_api_key),
) -> GenerateResponse:
    """Generate and validate code through Guardrails Guard.validate()."""
    enforce_rate_limit(request)
    try:
        gemini_client = get_gemini_client()
        raw_code = await gemini_client.generate_code(req.prompt, req.language)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        guard = get_guard(strict=req.strict)
        validation = guard.validate(raw_code)
        validated_code = validation.validated_output or raw_code
        passed = validation.validation_passed
    except Exception as e:
        # Fail closed so validator/runtime issues never leak raw generated code.
        return GenerateResponse(
            code="",
            passed=False,
            issues=[
                ValidationIssue(
                    validator="guard",
                    message=f"Validation error: {str(e)}",
                    severity="error",
                )
            ],
            raw_code=None,
        )

    issues = extract_validation_issues(validation)

    return GenerateResponse(
        code=validated_code,
        passed=passed,
        issues=issues,
        raw_code=raw_code if not passed else None,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
