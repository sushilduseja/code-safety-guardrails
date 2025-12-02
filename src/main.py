from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.gemini_client import GeminiClient
from src.guardrails_config import run_validators


class GenerateRequest(BaseModel):
    prompt: str = Field(..., description="User prompt describing the desired code")
    language: str = Field("python", description="Target programming language")


class GenerateResponse(BaseModel):
    code: str
    validation_report: Dict[str, Any]
    passed: bool


app = FastAPI(title="Code Safety Guardrails", version="0.1.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
_gemini_client = GeminiClient()


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/generate", response_model=GenerateResponse)
async def generate(req: GenerateRequest) -> GenerateResponse:
    try:
        code = await _gemini_client.generate_code(req.prompt, req.language.lower())
    except Exception as exc:  # pragma: no cover - external dependency errors
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    validation = run_validators(code)

    if not validation["passed"]:
        # For MVP we still return the (possibly sanitized) code, but mark as failed.
        # A stricter option is to raise 400 here.
        return GenerateResponse(
            code=validation["sanitized_code"],
            validation_report=validation["report"],
            passed=False,
        )

    return GenerateResponse(
        code=validation["sanitized_code"],
        validation_report=validation["report"],
        passed=True,
    )
