"""Build the configured provider. Overrides are explicit and never silent."""

from __future__ import annotations

from nymbric.core.config import AgentModelConfig
from nymbric.core.errors import ConfigError, ProviderUnavailable
from nymbric.models.providers.anthropic import AnthropicProvider
from nymbric.models.providers.mock import MockProvider
from nymbric.models.providers.ollama import OllamaProvider
from nymbric.models.providers.openai_provider import OpenAICompatibleProvider, OpenAIProvider


def build_provider(config: AgentModelConfig):
    provider = config.provider.strip().lower()
    if provider == "mock":
        return MockProvider(model=config.model or "mock-deterministic")
    if provider == "ollama":
        return OllamaProvider(
            config.model,
            base_url=config.base_url or "http://127.0.0.1:11434",
            timeout_s=config.timeout_s,
            temperature=config.temperature,
            num_ctx=config.num_ctx,
        )
    if provider == "openai":
        return OpenAIProvider(config.model, timeout_s=config.timeout_s, temperature=config.temperature, base_url=config.base_url)
    if provider in {"openai_compatible", "openai-compatible"}:
        if not config.base_url:
            raise ProviderUnavailable(
                "openai_compatible requires base_url. Nymbric did not fall back to another provider."
            )
        return OpenAICompatibleProvider(
            config.model,
            base_url=config.base_url,
            timeout_s=config.timeout_s,
            temperature=config.temperature,
        )
    if provider == "anthropic":
        return AnthropicProvider(config.model, timeout_s=config.timeout_s, temperature=config.temperature, base_url=config.base_url or "https://api.anthropic.com")
    raise ConfigError(
        f"Unknown provider '{config.provider}'. Expected mock, ollama, openai, openai_compatible, or anthropic."
    )
