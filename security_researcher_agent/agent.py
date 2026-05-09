from __future__ import annotations

from pathlib import Path

from .config import AgentConfig
from .models import build_model_client
from .planner import Planner
from .reporter import Reporter, RunArtifacts
from .scope import TargetScope
from .tools import CommandRejected, CommandResult, ToolManager


class SecurityResearcherAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.scope = TargetScope.parse(config.target)
        self.model = build_model_client(
            provider=config.provider,
            model=config.model,
            openai_base_url=config.openai_base_url,
            ollama_base_url=config.ollama_base_url,
            api_key=config.api_key,
        )
        self.tools = ToolManager(work_dir=Path.cwd(), timeout_seconds=config.timeout_seconds)
        self.planner = Planner(self.model)
        self.reporter = Reporter(self.model)

    def run(self) -> RunArtifacts:
        if not self.config.assume_authorized:
            raise ValueError("Pass --assume-authorized to confirm the target is in scope.")

        inventory = self.tools.inventory(self.config.tools)
        install_results: list[CommandResult] = []
        if self.config.install_missing:
            install_results = self.tools.install_missing(self.config.tools)
            inventory = self.tools.inventory(self.config.tools)

        plan = self.planner.plan(
            target=self.scope.host,
            inventory=inventory,
            max_steps=self.config.max_steps,
        )
        results: list[CommandResult] = list(install_results)
        rejected: list[str] = []
        for item in plan:
            try:
                results.append(self.tools.run(name=item.name, command=item.command, scope=self.scope))
            except CommandRejected as exc:
                rejected.append(f"{item.name}: {item.command} ({exc})")
        return self.reporter.write(
            target=self.scope.host,
            output_dir=self.config.output_dir,
            inventory=inventory,
            plan=plan,
            results=results,
            rejected=rejected,
        )

