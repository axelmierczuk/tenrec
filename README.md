<p align="center">
  <img alt="logo" src="https://raw.githubusercontent.com/axelmierczuk/tenrec/refs/heads/main/tenrec/documentation/static/_media/icon.svg" width="30%" height="30%">
</p>

# Tenrec

[![PyPI](https://img.shields.io/pypi/v/tenrec)](https://pypi.org/project/tenrec/)
[![Python Version](https://img.shields.io/pypi/pyversions/tenrec)](https://pypi.org/project/tenrec/)
[![License](https://img.shields.io/pypi/l/tenrec)](https://img.shields.io/pypi/l/tenrec)

A headless, extendable, multi-session MCP framework for IDA Pro, built with [ida-domain](https://ida-domain.docs.hex-rays.com/) and FastMCP.

## Features

- **Headless**: No GUI required, powered by ida-domain
- **Multi-session**: Analyze multiple binaries simultaneously
- **Extensible**: Custom plugin support via entry points
- **Auto-docs**: Generate documentation from plugins

### Built-in Plugins

| Plugin | Description |
|--------|-------------|
| Functions | Analyze functions, boundaries, pseudocode |
| Xrefs | Data and code cross-references |
| Names | Symbol naming and demangling |
| Comments | Code comments (regular, repeatable) |
| Strings | String literal search/analysis |
| Segments | Memory segment queries |
| Bytes | Binary data read/patch |
| Types | Type information and structures |
| Entries | Entry points and exports |

For complete plugin documentation, see [tenrec docs](https://axelmierczuk.github.io/tenrec/#/).

> [!NOTE]
> Community plugins: [tenrec-plugins](https://github.com/axelmierczuk/tenrec-plugins)

## Demo

Solving Flare-On 9 Challenge 4 (darn mice) with a single prompt using tenrec and Claude Code:

> Use tenrec to open a session and reverse the binary. Focus on getting a high-level understanding by finding entry points and tracing execution flow. Rename variables and functions as you work. The xref plugin can help. Look for a flag in email format.

https://github.com/user-attachments/assets/3eb442dd-9b7a-44a6-836b-b73f99f4c2f3

Challenge write-up: [04-darn-mice.pdf](https://services.google.com/fh/files/misc/04-darn-mice.pdf) | Binary: [fareedfauzi/Flare-On-Challenges](https://github.com/fareedfauzi/Flare-On-Challenges)

## Installation

### Prerequisites

- Python 3.10+
- IDA Pro 9.1+

### Install

```bash
uv tool install tenrec
```

Verify installation:

```bash
uv tool list    # Should show tenrec
which tenrec    # Should show path to executable
```

### Set IDA Directory

```bash
# macOS
export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"

# Linux
export IDADIR="/opt/idapro"

# Windows (PowerShell, as Administrator)
setx IDADIR "C:\Program Files\IDA Pro" /M
```

## Quick Start

### 1. Install MCP Client

```bash
tenrec install
```

Select your MCP client from the list (Claude Code, Cursor, Windsurf, etc.).

### 2. Run Server

```bash
tenrec run
```

The server runs with stdio transport by default. Use `--transport sse` for SSE.

### 3. Plugin Management

```bash
# Add plugin
tenrec plugins add --plugin "package-name"
tenrec plugins add --plugin "/path/to/plugin"
tenrec plugins add --plugin "git+https://github.com/user/repo"

# List plugins
tenrec plugins list

# Remove plugin
tenrec plugins remove --dist plugin_name
```

### 4. Generate Documentation

```bash
tenrec docs -p tenrec/plugins/plugins
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Plugin Development](agent_docs/plugin-development.md) | Creating custom plugins |
| [CLI Reference](agent_docs/cli-reference.md) | Complete command reference |
| [Architecture](agent_docs/architecture.md) | System design |
| [Testing](agent_docs/testing.md) | Testing patterns |
| [Integrations](agent_docs/integrations.md) | MCP client setup (including Codex) |
| [Contributing](agent_docs/contributing.md) | Development setup and guidelines |
| [Roadmap](agent_docs/roadmap.md) | Future plans |

## Creating Plugins

```python
from tenrec.plugins.models import PluginBase, Instructions, operation

class MyPlugin(PluginBase):
    """Plugin description."""

    name = "my_plugin"  # Must be snake_case
    version = "1.0.0"   # Must be semver

    instructions = Instructions(
        purpose="What this plugin does",
        interaction_style=["How to use effectively"],
        examples=["my_plugin_operation()"],
        anti_examples=["What NOT to do"],
    )

    @operation()
    def my_operation(self) -> dict:
        """Operation docstring for LLM guidance."""
        # Access IDA via self.database
        return {"result": "value"}
```

Package with entry point in `pyproject.toml`:

```toml
[project.entry-points."tenrec.plugins"]
my_plugin = "my_package:MyPlugin"
```

See [Plugin Development Guide](agent_docs/plugin-development.md) for complete documentation.

## Known Issues

- Windows support is in progress. See [Issue #9](https://github.com/axelmierczuk/tenrec/issues/9).

## Contributing

See [Contributing Guide](agent_docs/contributing.md) for development setup and guidelines.

## License

MIT
