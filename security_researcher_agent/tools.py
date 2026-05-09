from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
import shutil
import subprocess
import time

from .scope import TargetScope


ALLOWED_BINARIES = {
    "curl",
    "dig",
    "host",
    "nmap",
    "nikto",
    "nuclei",
    "sslscan",
    "testssl.sh",
    "whatweb",
    "whois",
}

INSTALL_COMMANDS = {
    "curl": "sudo apt-get update && sudo apt-get install -y curl",
    "dig": "sudo apt-get update && sudo apt-get install -y dnsutils",
    "host": "sudo apt-get update && sudo apt-get install -y dnsutils",
    "nmap": "sudo apt-get update && sudo apt-get install -y nmap",
    "nikto": "sudo apt-get update && sudo apt-get install -y nikto",
    "sslscan": "sudo apt-get update && sudo apt-get install -y sslscan",
    "testssl.sh": "sudo apt-get update && sudo apt-get install -y testssl.sh",
    "whatweb": "sudo apt-get update && sudo apt-get install -y whatweb",
    "whois": "sudo apt-get update && sudo apt-get install -y whois",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}


@dataclass(frozen=True)
class ToolStatus:
    name: str
    available: bool
    path: str | None


@dataclass(frozen=True)
class CommandResult:
    name: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class CommandRejected(RuntimeError):
    pass


class ToolManager:
    def __init__(self, *, work_dir: Path, timeout_seconds: int) -> None:
        self.work_dir = work_dir
        self.timeout_seconds = timeout_seconds

    def inventory(self, tools: tuple[str, ...]) -> list[ToolStatus]:
        return [
            ToolStatus(name=tool, available=shutil.which(tool) is not None, path=shutil.which(tool))
            for tool in tools
        ]

    def install_missing(self, tools: tuple[str, ...]) -> list[CommandResult]:
        results: list[CommandResult] = []
        for status in self.inventory(tools):
            if status.available:
                continue
            command = INSTALL_COMMANDS.get(status.name)
            if command:
                results.append(self._run_shell(name=f"install_{status.name}", command=command))
        return results

    def run(self, *, name: str, command: str, scope: TargetScope) -> CommandResult:
        safe_command = command.replace("{target}", scope.host)
        self._validate_command(safe_command, scope)
        return self._run_exec(name=name, command=safe_command)

    def _validate_command(self, command: str, scope: TargetScope) -> None:
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            raise CommandRejected(f"Invalid shell quoting: {exc}") from exc
        if not argv:
            raise CommandRejected("Empty command.")
        binary = Path(argv[0]).name
        if binary not in ALLOWED_BINARIES:
            raise CommandRejected(f"Command is not in the security tool allowlist: {binary}")
        if not any(scope.contains_token(token) for token in argv[1:]):
            raise CommandRejected("Command does not reference the configured target.")
        blocked = {"-oX", "-oA", "--script=http-shellshock", "--script=smb-vuln-ms17-010"}
        if any(token in blocked for token in argv):
            raise CommandRejected("Command includes a blocked high-risk option.")

    def _run_exec(self, *, name: str, command: str) -> CommandResult:
        argv = shlex.split(command)
        start = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=self.work_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            return CommandResult(
                name=name,
                command=command,
                returncode=completed.returncode,
                stdout=completed.stdout[-20000:],
                stderr=completed.stderr[-12000:],
                duration_seconds=round(time.monotonic() - start, 2),
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                name=name,
                command=command,
                returncode=124,
                stdout=(exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else "",
                stderr=f"Timed out after {self.timeout_seconds} seconds.",
                duration_seconds=round(time.monotonic() - start, 2),
            )
        except FileNotFoundError as exc:
            return CommandResult(
                name=name,
                command=command,
                returncode=127,
                stdout="",
                stderr=f"Tool not found: {Path(argv[0]).name}",
                duration_seconds=round(time.monotonic() - start, 2),
            )

    def _run_shell(self, *, name: str, command: str) -> CommandResult:
        start = time.monotonic()
        completed = subprocess.run(
            command,
            cwd=self.work_dir,
            capture_output=True,
            text=True,
            timeout=max(self.timeout_seconds, 600),
            check=False,
            shell=True,
        )
        return CommandResult(
            name=name,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout[-20000:],
            stderr=completed.stderr[-12000:],
            duration_seconds=round(time.monotonic() - start, 2),
        )
