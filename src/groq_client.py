import asyncio
import os
from typing import Literal

from groq import AsyncGroq
from dotenv import load_dotenv

from config.prompts import SYSTEM_PROMPT

load_dotenv()

MODEL_NAME = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
TIMEOUT_SECONDS = float(os.getenv("GROQ_TIMEOUT_SECONDS", "30"))


class GroqClient:
    """Thin wrapper around the Groq API for secure code generation."""

    def __init__(self, model: str = MODEL_NAME, temperature: float = 0.3) -> None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY is not set")

        self.client = AsyncGroq(api_key=api_key)
        self.model = model
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

        response = await asyncio.wait_for(
            self._call_model(full_prompt),
            timeout=TIMEOUT_SECONDS,
        )
        normalized = self.normalize_generated_code(response)
        if not normalized:
            raise RuntimeError("Groq returned an empty response")
        return normalized

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

    @staticmethod
    def normalize_generated_code(response: str) -> str:
        """Strip markdown wrappers that some models return despite prompt constraints."""
        text = response.strip()
        if not text:
            return ""

        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        return text

    async def _call_model(self, prompt: str) -> str:
        completion = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.temperature,
        )
        return completion.choices[0].message.content or ""
