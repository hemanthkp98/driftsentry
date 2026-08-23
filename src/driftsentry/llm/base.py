"""Abstract base class for LLM providers in DriftSentry.

All providers (Claude, Gemini, etc.) must implement the ``complete`` method,
which accepts a system prompt and a user prompt and returns the raw text response.
Prompt structuring and JSON schema validation are handled centrally in LLMAnalyzer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """Common interface every LLM provider must implement."""

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        """Send system_prompt and user_prompt to the model and return raw text.

        Args:
            system_prompt: System / role instructions.
            user_prompt: User input containing drift data and instructions.
            max_tokens: Maximum tokens to generate.

        Returns:
            The model's text response.
        """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name, e.g. 'claude' or 'gemini'."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """The specific model identifier being used."""
