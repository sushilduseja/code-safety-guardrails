# Code Safety Guardrails

AI-powered code generation with integrated security validation using Google Gemini and Guardrails AI.

## Quick Start

### Setup
```bash
git clone https://github.com/sushilduseja/code-safety-guardrails.git
cd code-safety-guardrails
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your GOOGLE_API_KEY from https://ai.google.dev/
```

### Run
```bash
uvicorn src.main:app --reload
```

Then visit **http://localhost:8000/static/demo_ui.html** for interactive demo or **http://localhost:8000/docs** for API docs.

## Features

- ✅ **4 Security Validators**: SQL injection, command execution, secrets detection, malicious imports
- ✅ **Auto-Fix Capabilities**: Parameterized SQL, shell=False conversion, secrets redaction
- ✅ **Guardrails AI Integration**: Proper @register_validator pattern with PassResult/FailResult
- ✅ **Web Demo**: Interactive UI for testing code generation
- ✅ **100% Tests Passing**: 23 comprehensive unit tests

## API

### `POST /generate` - Generate and validate code
```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
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

## Validators

| Validator | Detects | Auto-Fix |
|-----------|---------|----------|
| **SQL Injection** | f-strings, concatenation in SQL | Suggests parameterized queries |
| **Command Execution** | os.system(), eval(), subprocess with shell=True | Converts to safe subprocess.run() |
| **Secrets** | AWS keys, GitHub tokens, passwords, private keys | Auto-redacts |
| **Malicious Imports** | pickle, ctypes, socket, __import__() | Blocks dangerous modules |

## Testing

```bash
pytest tests/test_validators.py -v
# Output: 23 passed
```

## Project Structure
```
src/
├── main.py                      # FastAPI app with Guard.validate() integration
├── gemini_client.py             # Google Gemini API wrapper
└── validators/
    ├── sql_injection.py         # SQLInjectionValidator
    ├── command_execution.py     # CommandExecutionValidator
    ├── secrets_scanner.py       # SecretsValidator
    ├── malicious_imports.py     # MaliciousImportsValidator
    └── factory.py               # create_code_guard() function
tests/
└── test_validators.py           # 23 unit tests
static/
└── demo_ui.html                 # Interactive web demo
```

## Real-World Examples

See [EXAMPLES.md](./EXAMPLES.md) for practical usage patterns and validator behavior.

## Dependencies

- FastAPI, Uvicorn — Web framework
- Guardrails AI — Validation framework  
- Google Generative AI — Gemini API
- Pydantic — Data validation
- pytest — Testing

## License

MIT
