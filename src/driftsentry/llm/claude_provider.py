"""Anthropic Claude provider for DriftSentry.

Uses the Anthropic Python SDK with optional extended thinking enabled.
Requires the ``ANTHROPIC_API_KEY`` environment variable to be set.

Default model: claude-sonnet-4-6 (fast, cost-effective for code generation)
"""

from __future__ import annotations

import os
from typing import Any

from driftsentry.core.config import LLMConfig
from driftsentry.llm.base import BaseLLMProvider

DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6"


class ClaudeProvider(BaseLLMProvider):
    """LLM provider backed by Anthropic Claude."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required for Claude AI features. "
                "Install it with: pip install 'driftsentry[ai]' or pip install anthropic"
            ) from exc

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise OSError(
                "ANTHROPIC_API_KEY environment variable is not set. "
                "Please set ANTHROPIC_API_KEY or configure another provider."
            )

        self._model = config.model if config and config.model else DEFAULT_CLAUDE_MODEL
        self._thinking_budget = config.thinking_budget if config else 5000
        self._client: Any = anthropic.Anthropic(api_key=api_key)

    @property
    def provider_name(self) -> str:
        return "claude"

    @property
    def model_name(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        """Call Claude Messages API and return text response."""
        params: dict[str, object] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }

        # Enable thinking if budget is set and model supports it
        if self._thinking_budget > 0:
            params["thinking"] = {"type": "enabled", "budget_tokens": self._thinking_budget}

        response: Any = self._client.messages.create(**params)

        text_parts: list[str] = [
            str(getattr(block, "text", ""))
            for block in getattr(response, "content", [])
            if getattr(block, "type", None) == "text"
        ]
        if not text_parts:
            raise RuntimeError("Claude returned no text content in its response.")
        return str("\n".join(text_parts))
