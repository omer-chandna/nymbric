"""Validated configuration with environment-variable interpolation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from nymbric.core.errors import ConfigError

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def interpolate(value: Any) -> Any:
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            found = os.environ.get(match.group(1))
            if found is not None and found != "":
                return found
            if match.group(2) is not None:
                return match.group(2)
            return ""

        return _ENV.sub(repl, value)
    if isinstance(value, dict):
        return {str(k): interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [interpolate(v) for v in value]
    return value


def find_config_dir(start: Path | None = None) -> Path | None:
    here = (start or Path.cwd()).resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "configs" / "models.yaml").exists():
            return candidate / "configs"
    return None


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a mapping.")
    return interpolate(raw)


class AgentModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    model: str
    temperature: float = 0
    timeout_s: float = 120
    max_retries: int = 2
    num_ctx: int = 8192
    base_url: str | None = None


class ModelsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_provider: str
    default_model: str
    agents: dict[str, AgentModelConfig] = Field(default_factory=dict)

    def for_agent(self, role: str, provider_override: str | None = None, model_override: str | None = None) -> AgentModelConfig:
        base = self.agents.get(role)
        if base is None:
            base = AgentModelConfig(provider=self.default_provider, model=self.default_model)
        data = base.model_dump()
        if provider_override:
            data["provider"] = provider_override
        if model_override:
            data["model"] = model_override
        elif provider_override and provider_override != base.provider:
            if provider_override == "mock":
                data["model"] = model_override or "mock-deterministic"
            elif model_override is None and provider_override == self.default_provider:
                data["model"] = self.default_model
        if not data["model"]:
            raise ConfigError(
                f"No model configured for role '{role}' on provider '{data['provider']}'. "
                "Set it in configs/models.yaml or the environment variable referenced there."
            )
        return AgentModelConfig.model_validate(data)


def default_models() -> ModelsFile:
    return ModelsFile(
        default_provider="ollama",
        default_model="qwen3:8b",
        agents={},
    )


def load_models(path: Path | None = None) -> ModelsFile:
    if path is None:
        directory = find_config_dir()
        if directory is None:
            return default_models()
        path = directory / "models.yaml"
    return ModelsFile.model_validate(load_yaml(path))


def load_mapping(name: str) -> dict[str, Any]:
    directory = find_config_dir()
    if directory is None:
        return {}
    path = directory / name
    if not path.exists():
        return {}
    return load_yaml(path)
