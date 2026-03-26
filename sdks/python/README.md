# Aegis Python SDK

Python client for [Aegis](https://github.com/your-org/aegis) -- the AI agent security guardrail proxy.

## Installation

```bash
pip install aegis-sdk
```

With framework adapters:

```bash
pip install aegis-sdk[langchain]
pip install aegis-sdk[openai-agents]
```

## Quick Start

```python
from aegis import AegisClient

client = AegisClient()  # connects to http://127.0.0.1:19002

# Evaluate a shell command
verdict = client.evaluate_shell("nmap -sV 10.0.0.1")
if verdict.denied:
    print(f"Blocked: {verdict.reason}")

# Evaluate an HTTP request
verdict = client.evaluate_http("POST", "https://api.example.com/data")
print(verdict.decision, verdict.source)
```

## Decorators

Guard your tool functions with zero boilerplate:

```python
from aegis import guarded_tool

@guarded_tool
def run_shell(command: str) -> str:
    import subprocess
    return subprocess.check_output(command, shell=True).decode()

run_shell("ls -la")       # passes through
run_shell("rm -rf /")     # raises AegisBlocked
```

## Async Support

```python
from aegis import AsyncAegisClient

async with AsyncAegisClient() as client:
    verdict = await client.evaluate_shell("whoami")
```

## LangChain Integration

```python
from langchain_community.tools import ShellTool
from aegis.adapters.langchain import guarded_tool

safe_shell = guarded_tool(ShellTool())
```

## OpenAI Agents SDK Integration

```python
from agents import Agent
from aegis.adapters.openai_agents import aegis_input_guardrail

agent = Agent(
    name="pentester",
    input_guardrails=[aegis_input_guardrail()],
)
```

## API Reference

### AegisClient / AsyncAegisClient

| Method | Description |
|---|---|
| `health()` | Check if Aegis is running |
| `stats()` | Get aggregate request statistics |
| `evaluate_shell(command, tool_name, cwd)` | Evaluate a shell command |
| `evaluate_http(method, url, headers, body)` | Evaluate an HTTP request |
| `secrets_status()` | Get secrets config status |
| `create_snapshot()` | Create a filesystem snapshot |
| `snapshot_diff(id)` | Get snapshot diff |
| `snapshot_rollback(id)` | Rollback to snapshot |
| `snapshot_commit(id)` | Commit snapshot |
| `logs()` | List audit log files |
| `log_entries(file, limit, decision)` | Read audit log entries |

## Development

```bash
pip install -e ".[dev]"
pytest
```
