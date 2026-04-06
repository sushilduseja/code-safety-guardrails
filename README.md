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

Optional:
- Set `CODE_SAFETY_API_KEY` to require the `X-API-Key` header on `POST /generate`
- Set `GROQ_TIMEOUT_SECONDS` to bound upstream model latency
- Set `RATE_LIMIT_REQUESTS_PER_MINUTE` to cap caller traffic to `/generate`

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
.impeccable.md
EXAMPLES.md
index.html
README.md
src/
|-- main.py
|-- groq_client.py
`-- validators/
    |-- sql_injection.py
    |-- command_execution.py
    |-- secrets_scanner.py
    |-- malicious_imports.py
    `-- factory.py
tests/
|-- test_api.py
|-- test_demo_ui.py
|-- test_groq_client.py
`-- test_validators.py
```

## Real-World Examples

See [EXAMPLES.md](./EXAMPLES.md) for practical validator examples. Some examples are illustrative and should not be treated as production guarantees.
See [.impeccable.md](./.impeccable.md) for the saved demo design context used to keep the portfolio UI consistent.

## Dependencies

- FastAPI, Uvicorn - Web framework
- Groq - LLM API
- Pydantic - Data validation
- pytest - Testing
- slowapi - Rate limiting

## License

MIT
