from __future__ import annotations

from dataclasses import dataclass
import json
import os
import urllib.error
import urllib.request


class ModelError(RuntimeError):
    pass


@dataclass
class ChatMessage:
    role: str
    content: str


class ModelClient:
    def complete(self, messages: list[ChatMessage]) -> str:
        raise NotImplementedError


class OpenAICompatibleClient(ModelClient):
    def __init__(self, *, model: str, base_url: str, api_key: str | None) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def complete(self, messages: list[ChatMessage]) -> str:
        if not self.api_key:
            raise ModelError("OPENAI_API_KEY is required for the openai provider.")
        payload = {
            "model": self.model,
            "messages": [message.__dict__ for message in messages],
            "temperature": 0.2,
        }
        data = _post_json(
            f"{self.base_url}/chat/completions",
            payload,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        return data["choices"][0]["message"]["content"]


class OllamaClient(ModelClient):
    def __init__(self, *, model: str, base_url: str) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")

    def complete(self, messages: list[ChatMessage]) -> str:
        payload = {
            "model": self.model,
            "messages": [message.__dict__ for message in messages],
            "stream": False,
            "options": {"temperature": 0.2},
        }
        data = _post_json(f"{self.base_url}/api/chat", payload, headers={})
        return data["message"]["content"]


class NullModelClient(ModelClient):
    """Deterministic local fallback when no model endpoint is configured."""

    def complete(self, messages: list[ChatMessage]) -> str:
        prompt = messages[-1].content.lower()
        if "json" in prompt and "commands" in prompt:
            return json.dumps(
                {
                    "commands": [
                        {
                            "name": "basic_dns",
                            "command": "host {target}",
                            "reason": "Resolve the target and collect baseline DNS data.",
                        },
                        {
                            "name": "http_headers",
                            "command": "curl -I --max-time 20 https://{target}",
                            "reason": "Collect HTTP response headers for quick web exposure review.",
                        },
                        {
                            "name": "top_ports",
                            "command": "nmap -Pn --top-ports 100 --open {target}",
                            "reason": "Identify commonly exposed TCP services.",
                        },
                    ]
                }
            )
        if "write a concise security assessment report" in prompt:
            return """# Security Assessment Report

## Executive Summary
The assessment completed with deterministic local analysis. Review the evidence for exposed services, response headers, TLS observations, scanner output, and missing-tool gaps.

## Scope
The configured target was the only intended assessment scope.

## Findings
No model-derived vulnerability claims were generated. Treat command output as the source of truth and manually validate any exposed services or scanner observations.

## Evidence
See the generated evidence file for full command output.

## Recommendations
Install the desired Linux security tools, rerun the agent with an AI model configured, remove unnecessary exposed services, and harden HTTP/TLS configuration where applicable.

## Limitations
This report used the no-model fallback and does not assign severity.
"""
        return "No model response available."


def build_model_client(
    *,
    provider: str,
    model: str,
    openai_base_url: str,
    ollama_base_url: str,
    api_key: str | None,
) -> ModelClient:
    if provider == "openai":
        if not api_key and not os.getenv("OPENAI_API_KEY"):
            return NullModelClient()
        return OpenAICompatibleClient(model=model, base_url=openai_base_url, api_key=api_key)
    if provider == "ollama":
        return OllamaClient(model=model, base_url=ollama_base_url)
    if provider == "none":
        return NullModelClient()
    raise ModelError(f"Unsupported provider: {provider}")


def _post_json(url: str, payload: dict, headers: dict[str, str]) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise ModelError(f"Model request failed: {exc}") from exc
