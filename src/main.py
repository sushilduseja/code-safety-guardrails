"""FastAPI application with custom ValidatorPipeline integration."""

import logging
import os
import sys
import time
import uuid
import json
import asyncio
import hashlib
import contextvars
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from datetime import datetime

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from src.groq_client import GroqClient
from src.validators.factory import get_pipeline
from src.db import init_db, resolve_key, connect
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

logger = logging.getLogger(__name__)

# Initialize DB
init_db()

# Metrics counters
_metrics = {
    "requests_total": {},  # (tenant, passed) -> count
    "validator_failures": {}, # validator -> count
    "latency_ms": [], # list of recent latencies to approx p50 and p95
}

def record_metric(tenant: str, passed: bool, validators_failed: List[str], latency: int):
    key = (tenant, passed)
    _metrics["requests_total"][key] = _metrics["requests_total"].get(key, 0) + 1
    for v in validators_failed:
        _metrics["validator_failures"][v] = _metrics["validator_failures"].get(v, 0) + 1
    _metrics["latency_ms"].append(latency)
    if len(_metrics["latency_ms"]) > 1000:
        _metrics["latency_ms"] = _metrics["latency_ms"][-1000:]

class GenerateRequest(BaseModel):
    """Request model for code generation."""
    prompt: str = Field(..., min_length=1, max_length=4000, description="User prompt describing the desired code")
    language: Literal["python"] = Field("python", description="Target programming language")
    strict: bool = Field(False, description="Strict validation mode")

class ValidationIssueModel(BaseModel):
    """Single validation issue."""
    validator: str
    message: str
    severity: str

class GenerateResponse(BaseModel):
    """Response model for code generation."""
    code: str
    passed: bool
    issues: List[ValidationIssueModel]
    raw_code: Optional[str] = None
    protected_code: Optional[str] = None

app = FastAPI(title="Code Safety Guardrails", version="1.0.0")

request_ctx = contextvars.ContextVar("request")

@app.middleware("http")
async def add_request_context(request: Request, call_next):
    token = request_ctx.set(request)
    try:
        response = await call_next(request)
        return response
    finally:
        request_ctx.reset(token)

def get_tenant_id(request: Request) -> str:
    return getattr(request.state, "tenant_id", request.client.host if request.client else "unknown")

limiter = Limiter(key_func=get_tenant_id, storage_uri=os.getenv("REDIS_URL", "memory://"))
app.state.limiter = limiter

app.add_middleware(SlowAPIMiddleware)

_groq_client: Optional[GroqClient] = None

def get_groq_client() -> GroqClient:
    global _groq_client
    if _groq_client is None:
        _groq_client = GroqClient()
    return _groq_client

def require_api_key(request: Request, x_api_key: Optional[str] = Header(default=None)) -> None:
    environment = os.getenv("ENVIRONMENT", "development").lower()
    
    if environment in {"development", "test"} and not x_api_key:
        request.state.tenant_id = "dev"
        request.state.rpm_limit = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
        return

    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    row = resolve_key(x_api_key)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    request.state.tenant_id = row['tenant_id']
    request.state.rpm_limit = row['rpm_limit']

def get_tenant_limit() -> str:
    request = request_ctx.get()
    limit = getattr(request.state, "rpm_limit", 60)
    return f"{limit}/minute"

@app.get("/health")
async def health():
    groq_ok = False
    try:
        client = get_groq_client()
        await asyncio.wait_for(client.client.models.list(), timeout=3.0)
        groq_ok = True
    except Exception:
        pass

    return JSONResponse(
        status_code=200 if groq_ok else 503,
        content={
            "status": "ok" if groq_ok else "degraded",
            "groq_reachable": groq_ok,
            "validators_loaded": len(get_pipeline().validators),
            "version": os.getenv("APP_VERSION", "dev"),
        }
    )

@app.get("/metrics")
async def metrics():
    lines = []
    for (tenant, passed), count in _metrics["requests_total"].items():
        lines.append(f'guardrails_requests_total{{tenant="{tenant}",passed="{str(passed).lower()}"}} {count}')
    
    for v, count in _metrics["validator_failures"].items():
        lines.append(f'guardrails_validator_failures_total{{validator="{v}"}} {count}')
        
    latencies = sorted(_metrics["latency_ms"])
    if latencies:
        p50 = latencies[int(len(latencies)*0.5)]
        p95 = latencies[int(len(latencies)*0.95)]
        lines.append(f'guardrails_latency_p50_ms {p50}')
        lines.append(f'guardrails_latency_p95_ms {p95}')
    else:
        lines.append(f'guardrails_latency_p50_ms 0')
        lines.append(f'guardrails_latency_p95_ms 0')
        
    return PlainTextResponse("\n".join(lines) + "\n")

@app.get("/audit")
def audit(
    tenant_id: str,
    passed: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    _auth: None = Depends(require_api_key)
):
    with connect() as conn:
        query = "SELECT * FROM audit_log WHERE tenant_id=?"
        params = [tenant_id]
        if passed is not None:
            query += " AND passed=?"
            params.append(1 if passed else 0)
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

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

def _log_audit(request_id, tenant_id, prompt_hash, language, strict, validators_run_json, issues_json, passed_int, raw_code_hash, protected_code_hash, latency_ms):
    try:
        with connect() as conn:
            conn.execute(
                """INSERT INTO audit_log (
                    request_id, tenant_id, prompt_hash, language, strict,
                    validators_run, issues_found, passed, raw_code_hash, protected_code_hash, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    request_id, tenant_id, prompt_hash, language, strict,
                    validators_run_json, issues_json, passed_int, raw_code_hash, protected_code_hash, latency_ms
                )
            )
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")

@app.post("/generate", response_model=GenerateResponse)
@limiter.limit(get_tenant_limit)
async def generate(
    request: Request,
    req: GenerateRequest,
    _auth: None = Depends(require_api_key),
) -> GenerateResponse:
    start_time = time.monotonic()
    request_id = str(uuid.uuid4())
    tenant_id = getattr(request.state, "tenant_id", "unknown")
    prompt_hash = hashlib.sha256(req.prompt.encode()).hexdigest()
    
    passed = False
    raw_code = ""
    validated_code = ""
    issues = []
    failed_validators = []
    
    validators_run = []
    
    try:
        groq_client = get_groq_client()
        raw_code = await groq_client.generate_code(req.prompt, req.language)
        
        pipeline = get_pipeline(strict=req.strict)
        validators_run = [getattr(v, "name", "unknown") for v in getattr(pipeline, "validators", [])]
        result = pipeline.validate(raw_code)
        
        passed = result.passed and len(result.issues) == 0
        validated_code = result.validated_output
        issues = [ValidationIssueModel(validator=i.validator, message=i.message, severity=i.severity) for i in result.issues]
        failed_validators = [i.validator for i in result.issues]
        
    except Exception as exc:
        issues.append(ValidationIssueModel(validator="pipeline", message=f"Validation error: {str(exc)}", severity="error"))
        passed = False
        validated_code = ""
        failed_validators.append("pipeline")
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        
        raw_code_hash = hashlib.sha256(raw_code.encode()).hexdigest() if raw_code else None
        protected_code_hash = hashlib.sha256(validated_code.encode()).hexdigest() if validated_code else None
        
        validators_run_json = json.dumps(validators_run)
        issues_json = json.dumps([i.model_dump() for i in issues])
        
        await asyncio.to_thread(
            _log_audit,
            request_id, tenant_id, prompt_hash, req.language, int(req.strict),
            validators_run_json, issues_json, int(passed), raw_code_hash, protected_code_hash, latency_ms
        )
            
        record_metric(tenant_id, passed, failed_validators, latency_ms)
        
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
