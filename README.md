# Security Researcher Agent

An AI-assisted local security research agent for authorized Linux assessments. It inventories common Linux security tools, optionally installs missing tools, asks a configured model for an assessment plan, executes approved commands non-interactively, and writes Markdown evidence and findings.

## Install

```bash
python -m pip install -e .
```

## Run

OpenAI-compatible endpoint:

```bash
export OPENAI_API_KEY=...
sra example.com --assume-authorized --provider openai --model gpt-4.1-mini
```

Ollama:

```bash
sra example.com --assume-authorized --provider ollama --model llama3.1
```

No model, deterministic fallback plan:

```bash
sra example.com --assume-authorized --provider none
```

Install missing Linux tools before running:

```bash
sra example.com --assume-authorized --install-missing
```

Reports are written to `reports/` by default.

## Tools

The default execution allowlist is:

- `whois`
- `dig`
- `host`
- `curl`
- `nmap`
- `sslscan`
- `testssl.sh`
- `nikto`
- `whatweb`
- `nuclei`

The agent does not pause for command approval during a run. Scope and authorization are supplied up front with `--assume-authorized`.
