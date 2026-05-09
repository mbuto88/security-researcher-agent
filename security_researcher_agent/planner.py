from __future__ import annotations

from dataclasses import dataclass
import json
from json import JSONDecodeError

from .models import ChatMessage, ModelClient
from .tools import ToolStatus


@dataclass(frozen=True)
class PlannedCommand:
    name: str
    command: str
    reason: str


SYSTEM_PROMPT = """You are a security researcher working only on an authorized target.
Return compact JSON and no prose. Use only these binaries when available:
whois, dig, host, curl, nmap, sslscan, testssl.sh, nikto, whatweb, nuclei.
Prefer low-noise enumeration and evidence collection. Do not include exploit payloads,
credential attacks, persistence, destructive actions, or commands against unrelated hosts."""


class Planner:
    def __init__(self, model: ModelClient) -> None:
        self.model = model

    def plan(self, *, target: str, inventory: list[ToolStatus], max_steps: int) -> list[PlannedCommand]:
        tool_lines = "\n".join(
            f"- {tool.name}: {'available' if tool.available else 'missing'}" for tool in inventory
        )
        prompt = f"""Target: {target}
Tool inventory:
{tool_lines}

Create up to {max_steps} commands as JSON:
{{
  "commands": [
    {{"name": "short_id", "command": "tool args {{target}}", "reason": "why"}}
  ]
}}
Use {{target}} exactly as the target placeholder."""
        content = self.model.complete(
            [ChatMessage("system", SYSTEM_PROMPT), ChatMessage("user", prompt)]
        )
        return self._parse_plan(content, max_steps=max_steps)

    def _parse_plan(self, content: str, *, max_steps: int) -> list[PlannedCommand]:
        text = content.strip()
        if text.startswith("```"):
            text = text.strip("`")
            text = text.removeprefix("json").strip()
        try:
            data = json.loads(text)
        except JSONDecodeError:
            return [
                PlannedCommand(
                    name="top_ports",
                    command="nmap -Pn --top-ports 100 --open {target}",
                    reason="Identify commonly exposed TCP services.",
                ),
                PlannedCommand(
                    name="http_headers",
                    command="curl -I --max-time 20 https://{target}",
                    reason="Collect HTTP response headers.",
                ),
            ][:max_steps]
        commands = []
        for item in data.get("commands", [])[:max_steps]:
            commands.append(
                PlannedCommand(
                    name=str(item["name"])[:48],
                    command=str(item["command"]),
                    reason=str(item.get("reason", "")),
                )
            )
        return commands
