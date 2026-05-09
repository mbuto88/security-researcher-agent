from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import ChatMessage, ModelClient, ModelError
from .planner import PlannedCommand
from .tools import CommandResult, ToolStatus


@dataclass(frozen=True)
class RunArtifacts:
    report_path: Path
    evidence_path: Path


class Reporter:
    def __init__(self, model: ModelClient) -> None:
        self.model = model

    def write(
        self,
        *,
        target: str,
        output_dir: Path,
        inventory: list[ToolStatus],
        plan: list[PlannedCommand],
        results: list[CommandResult],
        rejected: list[str],
    ) -> RunArtifacts:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        evidence_path = output_dir / f"evidence-{stamp}.md"
        report_path = output_dir / f"report-{stamp}.md"
        evidence = self._render_evidence(target, inventory, plan, results, rejected)
        evidence_path.write_text(evidence, encoding="utf-8")
        report = self._render_report(target, evidence)
        report_path.write_text(report, encoding="utf-8")
        return RunArtifacts(report_path=report_path, evidence_path=evidence_path)

    def _render_report(self, target: str, evidence: str) -> str:
        prompt = f"""Write a concise security assessment report for {target}.
Use these sections: Executive Summary, Scope, Findings, Evidence, Recommendations, Limitations.
Base every finding only on the evidence. If evidence is inconclusive, say so plainly.

Evidence:
{evidence[-50000:]}"""
        try:
            body = self.model.complete(
                [
                    ChatMessage("system", "You write clear defensive security research reports."),
                    ChatMessage("user", prompt),
                ]
            )
        except ModelError:
            body = self._fallback_report(target, evidence)
        return body.strip() + "\n"

    def _render_evidence(
        self,
        target: str,
        inventory: list[ToolStatus],
        plan: list[PlannedCommand],
        results: list[CommandResult],
        rejected: list[str],
    ) -> str:
        lines = [f"# Evidence for {target}", ""]
        lines.append("## Tool Inventory")
        for tool in inventory:
            status = "available" if tool.available else "missing"
            lines.append(f"- {tool.name}: {status}{f' ({tool.path})' if tool.path else ''}")
        lines.extend(["", "## Plan"])
        for item in plan:
            lines.append(f"- {item.name}: `{item.command}` - {item.reason}")
        if rejected:
            lines.extend(["", "## Rejected Commands"])
            lines.extend(f"- {item}" for item in rejected)
        lines.extend(["", "## Command Output"])
        for result in results:
            lines.extend(
                [
                    f"### {result.name}",
                    f"- Command: `{result.command}`",
                    f"- Return code: {result.returncode}",
                    f"- Duration: {result.duration_seconds}s",
                    "",
                    "```text",
                    result.stdout.strip() or "(no stdout)",
                    "```",
                ]
            )
            if result.stderr.strip():
                lines.extend(["", "stderr:", "```text", result.stderr.strip(), "```"])
            lines.append("")
        return "\n".join(lines)

    def _fallback_report(self, target: str, evidence: str) -> str:
        return f"""# Security Assessment Report: {target}

## Executive Summary
The assessment completed and produced local evidence. No model-generated analysis was available, so findings should be reviewed directly from the evidence.

## Scope
Target: {target}

## Findings
Review the command output in the evidence file for exposed services, HTTP headers, TLS posture, and scanner observations.

## Evidence
{evidence[-20000:]}

## Recommendations
Patch exposed services, remove unnecessary public listeners, harden TLS and HTTP headers, and validate scanner observations manually.

## Limitations
This fallback report does not infer severity or exploitability.
"""

