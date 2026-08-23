"""Unit tests for LLM provider abstraction and factory."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from driftsentry.core.config import DriftSentryConfig, LLMConfig
from driftsentry.llm import get_llm_provider
from driftsentry.llm.base import BaseLLMProvider


class DummyProvider(BaseLLMProvider):
    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        return "{}"

    @property
    def provider_name(self) -> str:
        return "dummy"

    @property
    def model_name(self) -> str:
        return "dummy-model"


def test_get_llm_provider_unsupported() -> None:
    cfg = LLMConfig(provider="unsupported_provider")
    with pytest.raises(ValueError, match="Unsupported LLM provider"):
        get_llm_provider(cfg)


def test_claude_provider_missing_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Mock anthropic import to succeed
    with patch.dict("sys.modules", {"anthropic": MagicMock()}):
        cfg = LLMConfig(provider="claude")
        with pytest.raises(EnvironmentError, match="ANTHROPIC_API_KEY"):
            get_llm_provider(cfg)


def test_gemini_provider_missing_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    # Mock google.genai import to succeed
    mock_google = MagicMock()
    with patch.dict("sys.modules", {"google": mock_google, "google.genai": mock_google.genai}):
        cfg = LLMConfig(provider="gemini")
        with pytest.raises(EnvironmentError, match="GEMINI_API_KEY"):
            get_llm_provider(cfg)


def test_claude_provider_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    mock_anthropic = MagicMock()
    mock_client = MagicMock()
    mock_anthropic.Anthropic.return_value = mock_client

    mock_text_block = MagicMock()
    mock_text_block.type = "text"
    mock_text_block.text = '{"hcl_results": []}'

    mock_response = MagicMock()
    mock_response.content = [mock_text_block]
    mock_client.messages.create.return_value = mock_response

    with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
        cfg = LLMConfig(provider="claude", model="claude-sonnet-4-6")
        provider = get_llm_provider(cfg)
        assert provider.provider_name == "claude"
        assert provider.model_name == "claude-sonnet-4-6"

        res = provider.complete("system", "user")
        assert res == '{"hcl_results": []}'
        mock_client.messages.create.assert_called_once()


def test_gemini_provider_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mock_google = MagicMock()
    mock_genai = MagicMock()
    mock_google.genai = mock_genai
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client

    mock_response = MagicMock()
    mock_response.text = '{"root_causes": []}'
    mock_client.models.generate_content.return_value = mock_response

    with patch.dict("sys.modules", {"google": mock_google, "google.genai": mock_genai}):
        cfg = LLMConfig(provider="gemini", model="gemini-2.5-flash")
        provider = get_llm_provider(cfg)
        assert provider.provider_name == "gemini"
        assert provider.model_name == "models/gemini-2.5-flash"

        res = provider.complete("system", "user")
        assert res == '{"root_causes": []}'


def test_config_llm_defaults() -> None:
    cfg = DriftSentryConfig()
    assert cfg.llm.enabled is False
    assert cfg.llm.provider == "claude"
    assert cfg.llm.max_items == 20
