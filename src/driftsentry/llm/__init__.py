"""LLM provider abstraction package for DriftSentry.

Factory usage:
    from driftsentry.llm import get_llm_provider
    provider = get_llm_provider(config.llm)
"""

from __future__ import annotations

from driftsentry.core.config import LLMConfig
from driftsentry.llm.base import BaseLLMProvider


def get_llm_provider(config: LLMConfig | None = None) -> BaseLLMProvider:
    """Instantiate and return the LLM provider specified in configuration.

    Args:
        config: LLMConfig object. Defaults to default LLMConfig if None.

    Returns:
        Configured BaseLLMProvider instance.

    Raises:
        ValueError: If provider name is unsupported.
        ImportError: If the provider's SDK package is missing.
        EnvironmentError: If the required API key environment variable is not set.
    """
    provider_name = (config.provider if config else "claude").lower().strip()

    if provider_name == "claude":
        from driftsentry.llm.claude_provider import ClaudeProvider

        return ClaudeProvider(config)
    elif provider_name == "gemini":
        from driftsentry.llm.gemini_provider import GeminiProvider

        return GeminiProvider(config)
    else:
        raise ValueError(
            f"Unsupported LLM provider '{provider_name}'. Supported providers: 'claude', 'gemini'."
        )


__all__ = ["BaseLLMProvider", "get_llm_provider"]
