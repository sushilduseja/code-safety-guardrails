# Code Safety Guardrails (MVP)

FastAPI-based gateway in front of Gemini with a custom validator pipeline for generated code.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env  # and fill in real keys
```

## Running

```bash
uvicorn src.main:app --reload
```

Open `/docs` for Swagger UI, or use `static/demo_ui.html` against the same origin.

## Testing

```bash
pytest
```
