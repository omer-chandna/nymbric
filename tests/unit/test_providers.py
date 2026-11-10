import json

import httpx
import pytest

from nymbric.core.config import AgentModelConfig, load_models
from nymbric.core.errors import ProviderUnavailable, StructuredOutputError
from nymbric.models.base import ModelRequest
from nymbric.models.providers._parse import parse_json_object
from nymbric.models.providers.ollama import OllamaProvider
from nymbric.models.providers.openai_provider import OpenAIProvider
from nymbric.models.router import build_provider


def test_invalid_json_is_rejected():
    with pytest.raises(StructuredOutputError):
        parse_json_object("this is not an object")


def test_ollama_connection_failure_does_not_imply_a_fallback():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    provider = OllamaProvider("qwen3:8b", base_url="http://ollama.invalid", client=httpx.Client(transport=httpx.MockTransport(handler)))
    status = provider.check()
    assert status.ok is False
    assert "did not switch" in status.detail


def test_ollama_parses_tool_calls_and_usage():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["model"] == "qwen3:8b"
        assert body["stream"] is False
        assert body["tools"]
        return httpx.Response(
            200,
            json={
                "message": {"content": "", "tool_calls": [{"function": {"name": "search_web", "arguments": {"query": "Ada"}}}]},
                "prompt_eval_count": 11,
                "eval_count": 4,
                "done": True,
            },
        )

    provider = OllamaProvider("qwen3:8b", client=httpx.Client(transport=httpx.MockTransport(handler)))
    response = provider.generate(
        ModelRequest(
            agent_role="web_research",
            messages=[{"role": "user", "content": "search"}],
            tools=[{"type": "function", "function": {"name": "search_web", "parameters": {"type": "object"}}}],
        )
    )
    assert response.tool_calls[0].name == "search_web"
    assert response.tool_calls[0].arguments == {"query": "Ada"}
    assert response.usage.total_tokens == 15


def test_openai_without_a_key_is_an_explicit_diagnostic(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    status = OpenAIProvider("gpt-test", api_key=None).check()
    assert status.ok is False
    assert "OPENAI_API_KEY" in status.detail
    assert "did not fall back" in status.detail


def test_unknown_provider_is_rejected():
    with pytest.raises(Exception):
        build_provider(AgentModelConfig(provider="secret-gateway", model="x"))


def test_config_interpolation(monkeypatch):
    monkeypatch.setenv("RESEARCH_MODEL", "qwen3:4b")
    config = load_models()
    assert config.for_agent("web_research").model == "qwen3:4b"
    assert config.for_agent("defender").model == "qwen3:8b"
