from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .agent import SecurityResearcherAgent
from .config import AgentConfig, DEFAULT_TOOLS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sra",
        description="Run an AI-assisted security research workflow against an authorized target.",
    )
    parser.add_argument("target", help="Authorized hostname, IP address, CIDR, or URL.")
    parser.add_argument("-o", "--output-dir", default="reports", type=Path)
    parser.add_argument("--provider", choices=["openai", "ollama", "none"], default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--max-steps", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--install-missing", action="store_true")
    parser.add_argument("--assume-authorized", action="store_true")
    parser.add_argument(
        "--tools",
        default=",".join(DEFAULT_TOOLS),
        help="Comma-separated tool allowlist to inventory and use.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    tools = tuple(tool.strip() for tool in args.tools.split(",") if tool.strip())
    config = AgentConfig.from_env(
        target=args.target,
        output_dir=args.output_dir,
        model=args.model,
        provider=args.provider,
        max_steps=args.max_steps,
        timeout_seconds=args.timeout,
        install_missing=args.install_missing,
        assume_authorized=args.assume_authorized,
        tools=tools,
    )
    try:
        artifacts = SecurityResearcherAgent(config).run()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"report: {artifacts.report_path}")
    print(f"evidence: {artifacts.evidence_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

