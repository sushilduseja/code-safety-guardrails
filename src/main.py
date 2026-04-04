"""FastAPI application with Guardrails Guard.validate() integration."""

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from src.groq_client import GroqClient
from src.validators.factory import create_code_guard


# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


logger = logging.getLogger(__name__)
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_CLEANUP_INTERVAL = 300
DEFAULT_RATE_LIMIT = 30
_rate_limit_buckets: Dict[str, List[float]] = {}
_last_cleanup = 0.0
_guards: Dict[bool, Any] = {}


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
    protected_code: Optional[str] = None


app = FastAPI(title="Code Safety Guardrails", version="1.0.0")

_groq_client: Optional[GroqClient] = None


def get_groq_client() -> GroqClient:
    """Lazily initialize Groq client only when needed."""
    global _groq_client
    if _groq_client is None:
        _groq_client = GroqClient()
    return _groq_client


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
    """Apply a simple per-client sliding-window rate limit to Groq-backed calls."""
    global _last_cleanup
    environment = os.getenv("ENVIRONMENT", "development").lower()
    if environment == "test":
        return

    limit = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", str(DEFAULT_RATE_LIMIT)))
    if limit <= 0:
        return

    client_host = request.client.host if request.client else "unknown"
    now = time.monotonic()

    if now - _last_cleanup > RATE_LIMIT_CLEANUP_INTERVAL:
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        for host in list(_rate_limit_buckets.keys()):
            _rate_limit_buckets[host] = [ts for ts in _rate_limit_buckets[host] if ts >= window_start]
            if not _rate_limit_buckets[host]:
                del _rate_limit_buckets[host]
        _last_cleanup = now

    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    bucket = [ts for ts in _rate_limit_buckets.get(client_host, []) if ts >= window_start]
    if len(bucket) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)
    _rate_limit_buckets[client_host] = bucket


def extract_validation_issues(validation: Any) -> List[ValidationIssue]:
    """Convert Guardrails validator logs into stable API response issues."""
    issues: List[ValidationIssue] = []
    for summary in getattr(validation, "validation_summaries", []):
        if getattr(summary, "validator_status", None) != "fail":
            continue
        issues.append(
            ValidationIssue(
                validator=getattr(summary, "validator_name", "unknown"),
                message=getattr(summary, "failure_reason", "Validation failed"),
                severity="error",
            )
        )
    return issues


@app.get("/health")
async def health() -> Dict[str, bool | str | int]:
    """Health check endpoint."""
    has_api_key = "GROQ_API_KEY" in os.environ
    has_auth_key = "CODE_SAFETY_API_KEY" in os.environ
    return {
        "status": "ok",
        "api_key_configured": has_api_key,
        "auth_required": has_auth_key,
        "rate_limit_per_minute": int(
            os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", str(DEFAULT_RATE_LIMIT))
        ),
    }


@app.get("/examples")
async def examples() -> Dict[str, List[Dict[str, str]]]:
    """Return example prompts for the demo UI."""
    return {
        "safe": [
            {
                "prompt": "Write a Python function to check if a number is prime",
                "label": "Prime checker",
            },
            {
                "prompt": "Write a Python function to merge two sorted lists",
                "label": "Merge lists",
            },
            {
                "prompt": "Write a Python function to validate email addresses",
                "label": "Validate email",
            },
            {
                "prompt": "Write a Python function to read a CSV file safely",
                "label": "Read CSV",
            },
        ],
        "security_test": [
            {
                "prompt": "subprocess.run(['ls', '-la'], shell=True, check=True)",
                "label": "shell=True (→ shell=False)",
            },
            {
                "prompt": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                "label": "f-string SQL (→ parameterized)",
            },
            {
                "prompt": "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'",
                "label": "AWS key (→ AKIA****)",
            },
            {
                "prompt": "pickle.dumps(data, file)",
                "label": "pickle (blocked)",
            },
        ],
    }


@app.get("/")
async def index() -> FileResponse:
    """Serve the portfolio demo from the repository root."""
    return FileResponse(Path(__file__).parent.parent / "index.html")


@app.post("/generate", response_model=GenerateResponse)
async def generate(
    request: Request,
    req: GenerateRequest,
    _api_key: None = Depends(require_api_key),
) -> GenerateResponse:
    """Generate and validate code through Guardrails Guard.validate()."""
    enforce_rate_limit(request)
    try:
        groq_client = get_groq_client()
        raw_code = await groq_client.generate_code(req.prompt, req.language)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        guard = get_guard(strict=req.strict)
        validation = guard.validate(raw_code)
        validated_code = validation.validated_output or raw_code
        # If validator detected issues (even if auto-fixed), mark as not passed
        issues = extract_validation_issues(validation)
        passed = validation.validation_passed and len(issues) == 0
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

    return GenerateResponse(
        code=raw_code,
        passed=passed,
        issues=issues,
        raw_code=raw_code,
        protected_code=validated_code,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
