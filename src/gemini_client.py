import asyncio
import os
from typing import Literal

import google.generativeai as genai
from dotenv import load_dotenv

from config.prompts import SYSTEM_PROMPT

load_dotenv()

MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
TIMEOUT_SECONDS = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "30"))


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
        language: Literal["python"] = "python",
    ) -> str:
        """Generate code for the given prompt and language.

        The system prompt is injected to steer the model towards secure patterns.
        """

        full_prompt = self.build_prompt(prompt, language)

        # Bound upstream latency so one slow model call cannot hang the request.
        response = await asyncio.wait_for(
            self._call_model(full_prompt),
            timeout=TIMEOUT_SECONDS,
        )
        if not response.strip():
            raise RuntimeError("Gemini returned an empty response")
        return response.strip()

    @staticmethod
    def build_prompt(prompt: str, language: Literal["python"] = "python") -> str:
        """Structure policy and task separately to reduce prompt override ambiguity."""
        return (
            "<SYSTEM_POLICY>\n"
            f"{SYSTEM_PROMPT}\n"
            "</SYSTEM_POLICY>\n\n"
            "<GENERATION_RULES>\n"
            f"Language: {language}\n"
            "Return code only.\n"
            "Do not include prose or markdown fences.\n"
            "</GENERATION_RULES>\n\n"
            "<UNTRUSTED_USER_TASK>\n"
            f"{prompt}\n"
            "</UNTRUSTED_USER_TASK>"
        )

    async def _call_model(self, prompt: str) -> str:
        # Using the sync client but wrapping it as async via FastAPI's threadpool
        # keeps this function compatible with FastAPI's async endpoints.
        from fastapi.concurrency import run_in_threadpool

        def _generate() -> str:
            from google.generativeai import GenerationConfig
            completion = self.model.generate_content(
                prompt,
                generation_config=GenerationConfig(temperature=self.temperature),
            )
            return getattr(completion, "text", "")

        return await run_in_threadpool(_generate)
