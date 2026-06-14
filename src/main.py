import json
import os
import sys
import time
import uuid
import asyncio
import contextvars
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from src.deps import get_code_generator, get_telemetry
from src.generator import CodeGenerator, DemoCodeGenerator, RealCodeGenerator
from src.groq_client import GroqClient
from src.telemetry import Telemetry, SQLiteAuditAdapter, PrometheusMetricsAdapter
from src.validators.factory import create_code_guard
from src.db import init_db, resolve_key, connect, sha256hex
from src.log_config import setup_logging, set_request_id, reset_request_id
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware

sys.path.insert(0, str(Path(__file__).parent.parent))

init_db()

SAFE_EXAMPLES = [
    {"prompt": "Write a Python function to check if a number is prime", "label": "Prime checker"},
    {"prompt": "Write a Python function to merge two sorted lists", "label": "Merge lists"},
    {"prompt": "Write a Python function to validate email addresses", "label": "Validate email"},
    {"prompt": "Write a Python function to read a CSV file safely", "label": "Read CSV"},
    {
        "prompt": "Write a Python factorial function that rejects negative numbers and handles zero correctly",
        "label": "Factorial edge case",
    },
]

SECURITY_TEST_EXAMPLES = [
    {"prompt": "subprocess.run(['ls', '-la'], shell=True, check=True)", "label": "shell=True (\u2192 shell=False)"},
    {
        "prompt": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        "label": "f-string SQL (\u2192 parameterized)",
    },
    {"prompt": "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'", "label": "AWS key (\u2192 AKIA****)"},
    {"prompt": "pickle.dumps(data, file)", "label": "pickle (blocked)"},
    {"prompt": "os.system('ls -la')", "label": "os.system (blocked)"},
    {"prompt": "api_key = 'sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'", "label": "API key (redacted)"},
    {
        "prompt": "import requests\nrequests.get('https://example.com', timeout=5)",
        "label": "requests (strict blocked)",
    },
]


class GenerateRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000, description="User prompt describing the desired code")
    language: Literal["python"] = Field("python", description="Target programming language")
    strict: bool = Field(False, description="Strict validation mode")


class ValidationIssueModel(BaseModel):
    validator: str
    message: str
    severity: str


class GenerateResponse(BaseModel):
    code: str
    passed: bool
    issues: List[ValidationIssueModel]
    raw_code: Optional[str] = None
    protected_code: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logging.info("Starting Code Safety Guardrails server")
    
    registry_path = Path(__file__).parent.parent / "config" / "demo_registry.json"
    if registry_path.exists():
        registry = json.loads(registry_path.read_text()).get("prompts", {})
    else:
        registry = {}

    groq = GroqClient()
    real_gen = RealCodeGenerator(groq)
    code_gen = DemoCodeGenerator(registry, real_gen)
    telemetry = Telemetry(SQLiteAuditAdapter(), PrometheusMetricsAdapter())

    app.state.code_generator = code_gen
    app.state.telemetry = telemetry

    yield
    logging.info("Shutting down Code Safety Guardrails server")


app = FastAPI(title="Code Safety Guardrails", version="1.0.0", lifespan=lifespan)

request_ctx = contextvars.ContextVar("request")


@app.middleware("http")
async def add_request_context(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    token_ctx = request_ctx.set(request)
    token_rid = set_request_id(request_id)
    try:
        response = await call_next(request)
        return response
    finally:
        request_ctx.reset(token_ctx)
        reset_request_id(token_rid)


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


_auth_logger = logging.getLogger("auth")


def require_api_key(request: Request, x_api_key: Optional[str] = Header(default=None)) -> None:
    environment = os.getenv("ENVIRONMENT", "development").lower()
    client_host = request.client.host if request.client else "unknown"

    if environment in {"development", "test"} and not x_api_key:
        request.state.tenant_id = "dev"
        request.state.rpm_limit = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
        return

    if not x_api_key:
        _auth_logger.warning("Auth failure: missing key from %s", client_host)
        raise HTTPException(status_code=401, detail="Missing API key")

    row = resolve_key(x_api_key)
    if not row:
        _auth_logger.warning("Auth failure: invalid key from %s", client_host)
        raise HTTPException(status_code=401, detail="Invalid API key")

    request.state.tenant_id = row["tenant_id"]
    request.state.rpm_limit = row["rpm_limit"]


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
            "validators_loaded": len(create_code_guard().validators),
            "version": os.getenv("APP_VERSION", "dev"),
        }
    )


@app.get("/metrics")
async def metrics(
    telemetry: Telemetry = Depends(get_telemetry),
    _auth: None = Depends(require_api_key),
):
    return PlainTextResponse(telemetry.metrics.render())


@app.get("/audit")
def audit(
    request: Request,
    passed: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    _auth: None = Depends(require_api_key),
):
    with connect() as conn:
        query = "SELECT * FROM audit_log WHERE tenant_id=?"
        params = [request.state.tenant_id]
        if passed is not None:
            query += " AND passed=?"
            params.append(1 if passed else 0)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


@app.get("/examples")
async def examples() -> Dict[str, List[Dict[str, str]]]:
    return {"safe": SAFE_EXAMPLES, "security_test": SECURITY_TEST_EXAMPLES}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(Path(__file__).parent.parent / "index.html")


@app.post("/generate", response_model=GenerateResponse)
@limiter.limit(get_tenant_limit)
async def generate(
    request: Request,
    req: GenerateRequest,
    generator: CodeGenerator = Depends(get_code_generator),
    telemetry: Telemetry = Depends(get_telemetry),
    _auth: None = Depends(require_api_key),
) -> GenerateResponse:
    start_time = time.monotonic()
    request_id = str(uuid.uuid4())
    tenant_id = getattr(request.state, "tenant_id", "unknown")
    prompt_hash = sha256hex(req.prompt)

    passed = False
    raw_code = ""
    validated_code = ""
    issues: list[ValidationIssueModel] = []

    validators_run: list[str] = []

    try:
        raw_code = await generator.generate(req.prompt, req.language)

        pipeline = create_code_guard(strict=req.strict)
        validators_run = [getattr(v, "name", "unknown") for v in pipeline.validators]
        result = pipeline.validate(raw_code)

        passed = result.passed and len(result.issues) == 0
        validated_code = result.validated_output
        issues = [ValidationIssueModel(validator=i.validator, message=i.message, severity=i.severity) for i in result.issues]

    except Exception as exc:
        issues.append(ValidationIssueModel(validator="pipeline", message=f"Validation error: {str(exc)}", severity="error"))
        passed = False
        validated_code = ""
    finally:
        latency_ms = int((time.monotonic() - start_time) * 1000)

        raw_code_hash = sha256hex(raw_code) if raw_code else None
        protected_code_hash = sha256hex(validated_code) if validated_code else None

        await telemetry.record(
            request_id, tenant_id, prompt_hash, req.language, req.strict,
            validators_run, [i.model_dump() for i in issues],
            passed, raw_code_hash, protected_code_hash, latency_ms,
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
