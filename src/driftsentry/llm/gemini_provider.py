"""Google Gemini provider for DriftSentry.

Uses the ``google-genai`` Python SDK.
Requires the ``GEMINI_API_KEY`` environment variable to be set.

Default model: gemini-2.5-flash
"""

from __future__ import annotations

import os
from typing import Any

from driftsentry.core.config import LLMConfig
from driftsentry.llm.base import BaseLLMProvider

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


class GeminiProvider(BaseLLMProvider):
    """LLM provider backed by Google Gemini via google-genai SDK."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        try:
            from google import genai  # type: ignore[import-not-found]
            from google.genai import (  # type: ignore[import-not-found]
                types as genai_types,
            )
        except ImportError as exc:
            raise ImportError(
                "The 'google-genai' package is required for Gemini AI features. "
                "Install it with: pip install 'driftsentry[ai]' or pip install google-genai"
            ) from exc

        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            raise OSError(
                "GEMINI_API_KEY environment variable is not set. "
                "Please set GEMINI_API_KEY or configure another provider."
            )

        model = config.model if config and config.model else DEFAULT_GEMINI_MODEL
        self._model = model if model.startswith("models/") else f"models/{model}"
        self._thinking_budget = config.thinking_budget if config else 5000
        self._client: Any = genai.Client(api_key=api_key)
        self._genai_types: Any = genai_types

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        """Call Gemini GenerateContent API and return text response."""
        config_kwargs: dict[str, object] = {
            "system_instruction": system_prompt,
            "response_mime_type": "application/json",
            "max_output_tokens": max_tokens,
        }

        if self._thinking_budget > 0:
            config_kwargs["thinking_config"] = self._genai_types.ThinkingConfig(
                thinking_budget=self._thinking_budget
            )

        response: Any = self._client.models.generate_content(
            model=self._model,
            contents=user_prompt,
            config=self._genai_types.GenerateContentConfig(**config_kwargs),
        )

        text = getattr(response, "text", "")
        if not text:
            raise RuntimeError("Gemini returned an empty response.")
        return str(text)
