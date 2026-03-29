# Code Safety Guardrails

AI-powered Python code generation with integrated security validation using Google Gemini and Guardrails AI.

## Quick Start

### Setup
```bash
git clone https://github.com/sushilduseja/code-safety-guardrails.git
cd code-safety-guardrails
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
pip install -r requirements.lock
cp .env.example .env
# Edit .env with your GOOGLE_API_KEY from https://ai.google.dev/
```

Optional:
- Set `CODE_SAFETY_API_KEY` to require the `X-API-Key` header on `POST /generate`
- Set `GEMINI_TIMEOUT_SECONDS` to bound upstream model latency
- Set `RATE_LIMIT_REQUESTS_PER_MINUTE` to cap caller traffic to `/generate`

### Run
```bash
uvicorn src.main:app --reload
```

Then visit **http://localhost:8000/static/demo_ui.html** for the demo or **http://localhost:8000/docs** for the API docs. The demo page includes an optional API key field for secured deployments.

## Features

- Python-focused validation for generated code
- 4 security validators: SQL injection, command execution, secrets detection, malicious imports
- Conservative auto-fix behavior for selected patterns
- Fail-closed validation responses when guard execution errors
- Optional shared-key auth and per-client rate limiting on `/generate`
- Interactive web demo for manual testing
- Validator tests plus API-level regression coverage
- Fully pinned dependency closure in `requirements.lock`

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

### `GET /health` - Health check
```bash
curl http://localhost:8000/health
```

Health responses include:
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
src/
|-- main.py
|-- gemini_client.py
`-- validators/
    |-- sql_injection.py
    |-- command_execution.py
    |-- secrets_scanner.py
    |-- malicious_imports.py
    `-- factory.py
tests/
|-- test_api.py
`-- test_validators.py
static/
`-- demo_ui.html
```

## Real-World Examples

See [EXAMPLES.md](./EXAMPLES.md) for practical validator examples. Some examples are illustrative and should not be treated as production guarantees.

## Dependencies

- FastAPI, Uvicorn - Web framework
- Guardrails AI - Validation framework
- Google Generative AI - Gemini API
- Pydantic - Data validation
- pytest - Testing

## License

MIT
