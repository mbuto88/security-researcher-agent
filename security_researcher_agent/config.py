from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os


DEFAULT_TOOLS = (
    "whois",
    "dig",
    "host",
    "curl",
    "nmap",
    "sslscan",
    "testssl.sh",
    "nikto",
    "whatweb",
    "nuclei",
)


@dataclass(frozen=True)
class AgentConfig:
    target: str
    output_dir: Path
    model: str = "gpt-4.1-mini"
    provider: str = "openai"
    openai_base_url: str = "https://api.openai.com/v1"
    ollama_base_url: str = "http://localhost:11434"
    api_key: str | None = None
    max_steps: int = 12
    timeout_seconds: int = 180
    install_missing: bool = False
    assume_authorized: bool = False
    tools: tuple[str, ...] = field(default_factory=lambda: DEFAULT_TOOLS)

    @classmethod
    def from_env(
        cls,
        *,
        target: str,
        output_dir: Path,
        model: str | None,
        provider: str | None,
        max_steps: int,
        timeout_seconds: int,
        install_missing: bool,
        assume_authorized: bool,
        tools: tuple[str, ...] | None = None,
    ) -> "AgentConfig":
        chosen_provider = provider or os.getenv("SRA_MODEL_PROVIDER", "openai")
        chosen_model = model or os.getenv("SRA_MODEL", "gpt-4.1-mini")
        return cls(
            target=target,
            output_dir=output_dir,
            model=chosen_model,
            provider=chosen_provider,
            openai_base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            api_key=os.getenv("OPENAI_API_KEY"),
            max_steps=max_steps,
            timeout_seconds=timeout_seconds,
            install_missing=install_missing,
            assume_authorized=assume_authorized,
            tools=tools or DEFAULT_TOOLS,
        )

