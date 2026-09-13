"""Multi-provider LLM abstraction with vision support, cost tracking, and transmogrifier integration."""

from __future__ import annotations

import base64
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


# ---- Cost tracking ----


class LLMCallRecord(BaseModel):
    """Record of a single LLM API call."""

    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    duration_ms: float = 0.0
    has_vision: bool = False


class CostTracker:
    """Accumulates LLM call records for reporting."""

    def __init__(self) -> None:
        self.calls: list[LLMCallRecord] = []

    def record(self, call: LLMCallRecord) -> None:
        self.calls.append(call)

    @property
    def total_cost(self) -> float:
        return sum(c.estimated_cost_usd for c in self.calls)

    @property
    def total_input_tokens(self) -> int:
        return sum(c.input_tokens for c in self.calls)

    @property
    def total_output_tokens(self) -> int:
        return sum(c.output_tokens for c in self.calls)

    def summary(self) -> dict:
        return {
            "total_calls": len(self.calls),
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost, 4),
            "by_provider": self._by_provider(),
        }

    def _by_provider(self) -> dict:
        groups: dict[str, list[LLMCallRecord]] = {}
        for c in self.calls:
            groups.setdefault(c.provider, []).append(c)
        return {
            provider: {
                "calls": len(calls),
                "cost_usd": round(sum(c.estimated_cost_usd for c in calls), 4),
                "tokens": sum(c.input_tokens + c.output_tokens for c in calls),
            }
            for provider, calls in groups.items()
        }


# ---- Approximate pricing (USD per 1M tokens, as of early 2026) ----

_PRICING: dict[str, tuple[float, float]] = {
    # (input_per_1M, output_per_1M)
    "claude-opus-4": (15.0, 75.0),
    "claude-sonnet-4": (3.0, 15.0),
    "claude-haiku-4": (0.25, 1.25),
    "gpt-4o": (2.5, 10.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-2.5-flash": (0.15, 0.60),
}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD. Falls back to mid-range pricing if model unknown."""
    # Try prefix matching
    for key, (inp, out) in _PRICING.items():
        if model.startswith(key) or key.startswith(model):
            return (input_tokens * inp + output_tokens * out) / 1_000_000
    # Default: assume mid-range
    return (input_tokens * 3.0 + output_tokens * 15.0) / 1_000_000


# ---- Provider abstraction ----


class LLMProvider(ABC):
    """Abstract LLM provider with vision and text capabilities."""

    def __init__(self, model: str, cost_tracker: CostTracker | None = None) -> None:
        self.model = model
        self.cost_tracker = cost_tracker or CostTracker()

    @abstractmethod
    async def complete(
        self,
        system: str,
        messages: list[dict],
        max_tokens: int = 4096,
    ) -> str:
        """Text completion. Messages: [{"role": "user"|"assistant", "content": str}]"""

    @abstractmethod
    async def vision(
        self,
        system: str,
        prompt: str,
        image_path: str | Path,
        max_tokens: int = 4096,
    ) -> str:
        """Analyze an image with a text prompt."""

    def _record(self, input_tokens: int, output_tokens: int, duration_ms: float, has_vision: bool = False) -> None:
        self.cost_tracker.record(LLMCallRecord(
            provider=self.provider_name,
            model=self.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=_estimate_cost(self.model, input_tokens, output_tokens),
            duration_ms=duration_ms,
            has_vision=has_vision,
        ))

    @property
    @abstractmethod
    def provider_name(self) -> str: ...


def _load_image_b64(path: str | Path) -> str:
    return base64.standard_b64encode(Path(path).read_bytes()).decode()


class AnthropicProvider(LLMProvider):
    """Claude API provider."""

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def complete(self, system: str, messages: list[dict], max_tokens: int = 4096) -> str:
        import anthropic
        client = anthropic.AsyncAnthropic()
        start = time.monotonic()
        response = await client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        duration = (time.monotonic() - start) * 1000
        self._record(response.usage.input_tokens, response.usage.output_tokens, duration)
        return response.content[0].text

    async def vision(self, system: str, prompt: str, image_path: str | Path, max_tokens: int = 4096) -> str:
        import anthropic
        b64 = _load_image_b64(image_path)
        client = anthropic.AsyncAnthropic()
        start = time.monotonic()
        response = await client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": b64}},
                    {"type": "text", "text": prompt},
                ],
            }],
        )
        duration = (time.monotonic() - start) * 1000
        self._record(response.usage.input_tokens, response.usage.output_tokens, duration, has_vision=True)
        return response.content[0].text


class OpenAIProvider(LLMProvider):
    """OpenAI-compatible provider (OpenAI, Azure, local)."""

    @property
    def provider_name(self) -> str:
        return "openai"

    async def complete(self, system: str, messages: list[dict], max_tokens: int = 4096) -> str:
        from openai import AsyncOpenAI
        client = AsyncOpenAI()
        start = time.monotonic()
        full_messages = [{"role": "system", "content": system}] + messages
        response = await client.chat.completions.create(
            model=self.model,
            messages=full_messages,
            max_tokens=max_tokens,
        )
        duration = (time.monotonic() - start) * 1000
        usage = response.usage
        self._record(usage.prompt_tokens if usage else 0, usage.completion_tokens if usage else 0, duration)
        return response.choices[0].message.content or ""

    async def vision(self, system: str, prompt: str, image_path: str | Path, max_tokens: int = 4096) -> str:
        from openai import AsyncOpenAI
        b64 = _load_image_b64(image_path)
        client = AsyncOpenAI()
        start = time.monotonic()
        response = await client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}},
                    {"type": "text", "text": prompt},
                ]},
            ],
            max_tokens=max_tokens,
        )
        duration = (time.monotonic() - start) * 1000
        usage = response.usage
        self._record(usage.prompt_tokens if usage else 0, usage.completion_tokens if usage else 0, duration, True)
        return response.choices[0].message.content or ""


class GeminiProvider(LLMProvider):
    """Google Gemini provider."""

    @property
    def provider_name(self) -> str:
        return "gemini"

    async def complete(self, system: str, messages: list[dict], max_tokens: int = 4096) -> str:
        from google import genai
        client = genai.Client()
        # Convert messages to Gemini format
        contents = []
        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})
        start = time.monotonic()
        response = await client.aio.models.generate_content(
            model=self.model,
            contents=contents,
            config={"system_instruction": system, "max_output_tokens": max_tokens},
        )
        duration = (time.monotonic() - start) * 1000
        usage = response.usage_metadata
        self._record(
            usage.prompt_token_count if usage else 0,
            usage.candidates_token_count if usage else 0,
            duration,
        )
        return response.text or ""

    async def vision(self, system: str, prompt: str, image_path: str | Path, max_tokens: int = 4096) -> str:
        from google import genai
        from google.genai.types import Part
        image_bytes = Path(image_path).read_bytes()
        client = genai.Client()
        start = time.monotonic()
        response = await client.aio.models.generate_content(
            model=self.model,
            contents=[
                Part.from_bytes(data=image_bytes, mime_type="image/png"),
                prompt,
            ],
            config={"system_instruction": system, "max_output_tokens": max_tokens},
        )
        duration = (time.monotonic() - start) * 1000
        usage = response.usage_metadata
        self._record(
            usage.prompt_token_count if usage else 0,
            usage.candidates_token_count if usage else 0,
            duration,
            True,
        )
        return response.text or ""


class ApprenticeProvider(LLMProvider):
    """Apprentice adaptive routing provider. Routes between local and frontier models."""

    @property
    def provider_name(self) -> str:
        return "apprentice"

    async def complete(self, system: str, messages: list[dict], max_tokens: int = 4096) -> str:
        # Apprentice exposes an OpenAI-compatible API
        from openai import AsyncOpenAI
        client = AsyncOpenAI(base_url="http://localhost:8741/v1")
        start = time.monotonic()
        full_messages = [{"role": "system", "content": system}] + messages
        response = await client.chat.completions.create(
            model=self.model,
            messages=full_messages,
            max_tokens=max_tokens,
        )
        duration = (time.monotonic() - start) * 1000
        usage = response.usage
        self._record(usage.prompt_tokens if usage else 0, usage.completion_tokens if usage else 0, duration)
        return response.choices[0].message.content or ""

    async def vision(self, system: str, prompt: str, image_path: str | Path, max_tokens: int = 4096) -> str:
        # Apprentice vision support -- fall back to frontier for vision tasks
        from openai import AsyncOpenAI
        b64 = _load_image_b64(image_path)
        client = AsyncOpenAI(base_url="http://localhost:8741/v1")
        start = time.monotonic()
        response = await client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}},
                    {"type": "text", "text": prompt},
                ]},
            ],
            max_tokens=max_tokens,
        )
        duration = (time.monotonic() - start) * 1000
        usage = response.usage
        self._record(usage.prompt_tokens if usage else 0, usage.completion_tokens if usage else 0, duration, True)
        return response.choices[0].message.content or ""


# ---- Factory ----

_PROVIDER_DEFAULTS: dict[str, tuple[type[LLMProvider], str]] = {
    "anthropic": (AnthropicProvider, "claude-sonnet-4-20250514"),
    "openai": (OpenAIProvider, "gpt-4o"),
    "gemini": (GeminiProvider, "gemini-2.5-flash"),
    "apprentice": (ApprenticeProvider, "auto"),
}


def create_provider(
    provider: str = "anthropic",
    model: str | None = None,
    cost_tracker: CostTracker | None = None,
) -> LLMProvider:
    """Create an LLM provider by name."""
    if provider not in _PROVIDER_DEFAULTS:
        raise ValueError(f"Unknown provider: {provider}. Choose from: {list(_PROVIDER_DEFAULTS)}")
    cls, default_model = _PROVIDER_DEFAULTS[provider]
    return cls(model=model or default_model, cost_tracker=cost_tracker)


async def transmogrify_prompt(text: str, model: str) -> str:
    """Normalize prompt register via transmogrifier (if available)."""
    try:
        from transmogrifier.core import Transmogrifier
        t = Transmogrifier()
        result = t.translate(text, model=model)
        return result.output_text
    except ImportError:
        return text
    except Exception:
        return text
