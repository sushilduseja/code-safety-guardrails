import os
from typing import Literal

import google.generativeai as genai
from dotenv import load_dotenv

from config.prompts import SYSTEM_PROMPT

load_dotenv()

MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


class GeminiClient:
    """Thin wrapper around the Google Gemini API for secure code generation."""

    def __init__(self, model: str = MODEL_NAME, temperature: float = 0.3) -> None:
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("GOOGLE_API_KEY is not set")

        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)
        self.temperature = temperature

    async def generate_code(
        self,
        prompt: str,
        language: Literal["python", "javascript", "sql", "java", "typescript"] = "python",
    ) -> str:
        """Generate code for the given prompt and language.

        The system prompt is injected to steer the model towards secure patterns.
        """

        full_prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Language: {language}. "
            f"Generate only the code, no prose, no explanation.\n\n"
            f"Task: {prompt}"
        )

        # google-generativeai's async support is limited; use run_in_executor pattern from FastAPI if needed.
        response = await self._call_model(full_prompt)
        return response.strip()

    async def _call_model(self, prompt: str) -> str:
        # Using the sync client but wrapping it as async via FastAPI's threadpool
        # keeps this function compatible with FastAPI's async endpoints.
        from fastapi.concurrency import run_in_threadpool

        def _generate() -> str:
            completion = self.model.generate_content(
                prompt,
                generation_config={
                    "temperature": self.temperature,
                },
            )
            # google-generativeai returns a response object with .text
            return getattr(completion, "text", "")

        return await run_in_threadpool(_generate)
