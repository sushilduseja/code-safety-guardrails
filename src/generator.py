"""CodeGenerator seam — code generation with demo bypass and real generation adapters."""

from typing import Protocol

from src.groq_client import GroqClient


class CodeGenerator(Protocol):
    """Seam for code generation. Callers call generate(); adapters decide how."""

    async def generate(self, prompt: str, language: str = "python") -> str: ...


class RealCodeGenerator:
    """Adapter that calls the Groq API and normalizes the output."""

    def __init__(self, client: GroqClient) -> None:
        self._client = client

    async def generate(self, prompt: str, language: str = "python") -> str:
        raw = await self._client.generate_code(prompt, language)
        return GroqClient.normalize_generated_code(raw)


class DemoCodeGenerator:
    """Adapter that returns canned code from a registry for known prompts,
    falling back to a wrapped CodeGenerator for unmatched prompts."""

    def __init__(
        self,
        registry: dict[str, str],
        fallback: CodeGenerator | None = None,
    ) -> None:
        self._registry = registry
        self._fallback = fallback

    async def generate(self, prompt: str, language: str = "python") -> str:
        if prompt in self._registry:
            return self._registry[prompt]
        if self._fallback is not None:
            return await self._fallback.generate(prompt, language)
        return ""
