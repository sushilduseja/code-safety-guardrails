# Code Safety Guardrails [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/sushilduseja/code-safety-guardrails)

AI-powered Python code generation with integrated security validation using Groq.

## Quick Start

### Setup
```bash
git clone https://github.com/sushilduseja/code-safety-guardrails.git
cd code-safety-guardrails
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your GROQ_API_KEY from https://console.groq.com/
```

### Run
```bash
uvicorn src.main:app --reload
```

Then visit **http://localhost:8000/** for the demo.

The demo now has two paths:
- Safe prompts that go through normal model generation.
- Deterministic security demos that feed known-unsafe code into the validator pipeline so **Raw Output** and **Protected Output** visibly diverge when a rewrite or block happens.

## Deployment (Render)

Deploy as a **full-stack** app (not static):
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn src.main:app --host 0.0.0.0 --port $PORT`

Set these **Render dashboard secrets**:
- `GROQ_API_KEY` — Groq API key (required)
- `CODE_SAFETY_API_KEY` — optional shared key for `/generate` auth
- `RATE_LIMIT_REQUESTS_PER_MINUTE` — optional rate limit
- `ENVIRONMENT` — set to `production` to enforce API key auth

The frontend reads API URL from `VITE_API_URL` environment variable (local dev defaults to `window.location.origin`).

## Features

- Python-focused validation for generated code
- Internal, zero-dependency `ValidatorPipeline` (60 lines) replacing heavy guardrail libraries
- 4 security validators: SQL injection, command execution, secrets detection, malicious imports
- Safe code rewriting: AST-based SQL query rewriting, regex sanitization
- Deterministic negative demo cases for validator rewrites and hard blocks
- Fully local and isolated execution pipeline (~30 MB install footprint)
- Fails closed on parsing/AST errors and blocked patterns
- Persistent rate limiting via Redis and `slowapi`
- SQLite-backed API Key issuance per tenant
- SQLite-backed request auditing and query logging
- Endpoints for health checks (`/health`) and prometheus metrics (`/metrics`)
- **Structured, human-readable logging with request IDs for traceability**
- Interactive web demo for manual testing

## API

### `POST /generate` - Generate and validate Python code
```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Write a Python function to add two numbers", "language": "python"}'
```

If `CODE_SAFETY_API_KEY` is configured:
```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-for-shared-access" \
  -d '{"prompt": "Write a Python function to add two numbers", "language": "python"}'
```

Response:
```json
{
  "code": "def add(a, b):\n    return a + b",
  "passed": true,
  "issues": []
}
```

### `GET /health` - Configuration health snapshot
```bash
curl http://localhost:8000/health
```

This endpoint reports local configuration state. It does not verify Groq reachability or end-to-end request readiness.

Health responses include:
- `status`
- `api_key_configured`
- `auth_required`
- `rate_limit_per_minute`

### `GET /metrics` - Prometheus metrics (authenticated)
```bash
curl -H "X-API-Key: $YOUR_KEY" http://localhost:8000/metrics
```

Returns Prometheus-format metrics including request counts, validator failures, and latency percentiles. Requires API key authentication.

### `GET /audit` - Audit log (authenticated)
```bash
curl -H "X-API-Key: $YOUR_KEY" "http://localhost:8000/audit?tenant_id=$TENANT_ID"
```

Returns audit log entries for the authenticated tenant. Supports `passed`, `limit`, and `offset` query parameters.

### `GET /examples` - Example prompts
```bash
curl http://localhost:8000/examples
```

Returns safe and security-test example prompts.

## Validators

| Validator | Detects | Auto-Fix |
|-----------|---------|----------|
| **SQL Injection** | f-strings, concatenation in SQL | Suggests parameterized queries for supported patterns |
| **Command Execution** | os.system(), eval(), subprocess with shell=True | Safely rewrites `shell=True` only |
| **Secrets** | AWS keys, GitHub tokens, passwords, private keys | Auto-redacts |
| **Malicious Imports** | pickle, ctypes, socket, __import__() | Blocks dangerous modules |

## Testing
```bash
pytest tests -v
```

## Project Structure
```
.
├── AGENTS.md                 # Agent skills configuration
├── CONTEXT.md                # This file
├── README.md                 # Project documentation
├── CHANGELOG.md              # Release notes
├── VERSION                   # 0.0.1.0
├── .impeccable.md            # Design context/brand personality
├── config/
│   ├── prompts.py            # Groq system prompt
│   └── demo_registry.json    # Prompt→canned-code mappings (ADR-0006)
├── src/
│   ├── main.py               # FastAPI entry point + lifespan + Depends wiring
│   ├── deps.py               # Depends() injection functions (ADR-0008)
│   ├── groq_client.py        # Groq API wrapper
│   ├── generator.py          # CodeGenerator seam (ADR-0006)
│   ├── telemetry.py          # Telemetry + AuditAdapter + MetricsAdapter seams (ADR-0007)
│   ├── pipeline.py           # ValidatorPipeline (39 lines)
│   ├── db.py                 # SQLite persistence (56 lines)
│   ├── log_config.py         # Logging configuration and formatters
│   ├── cli.py                # API key CLI tool
│   └── validators/
│       ├── factory.py        # Pipeline builder (29 lines)
│       ├── sql_injection.py  # SQL injection detection (82 lines)
│       ├── command_execution.py  # Command execution (71 lines)
│       ├── secrets_scanner.py    # Secrets detection (32 lines)
│       └── malicious_imports.py  # Malicious imports (64 lines)
├── index.html                # Demo frontend
├── requirements.lock         # Frozen dependency tree for reproducible builds
├── tests/
│   ├── test_api.py           # API endpoint tests
│   ├── test_groq_client.py   # Groq client tests
│   ├── test_validators.py    # Validator unit tests
│   └── test_demo_ui.py       # DOM contract tests
└── docs/agents/              # Agent skill configuration
```

## Dependencies

- FastAPI, Uvicorn - Web framework
- Groq - LLM API
- Pydantic - Data validation
- pytest - Testing
- slowapi - Rate limiting
- python-dotenv - Environment variables
- redis - Rate limit storage (optional, defaults to in-memory)

## License

MIT