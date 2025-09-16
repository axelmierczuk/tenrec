
<p align="center">
  <img alt="logo" src="https://raw.githubusercontent.com/axelmierczuk/tenrec/refs/heads/main/tenrec/documentation/static/_media/icon.svg" width="30%" height="30%">
</p>

# Tenrec

[![PyPI](https://img.shields.io/pypi/v/tenrec)](https://pypi.org/project/tenrec/)
[![Python Version](https://img.shields.io/pypi/pyversions/tenrec)](https://pypi.org/project/tenrec/)
[![License](https://img.shields.io/pypi/l/tenrec)](https://img.shields.io/pypi/l/tenrec)

A headless, extendable, multi-session, IDA Pro MCP framework built with [ida-domain](https://ida-domain.docs.hex-rays.com/)
and FastMCP, inspired by [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp). Supports custom plugins 
for easy extension.

## Table of Contents
- [Overview](#overview)
- [Demo](#demo)
- [Installation](#installation)
- [Usage](#usage)
  - [install / uninstall](#install--uninstall)
  - [run](#run)
  - [docs](#docs)
  - [plugins](#plugins)
- [Creating Custom Plugins](#creating-custom-plugins)
- [Testing](#testing)
- [Contributing](#contributing)
- [Future Work](#future-work)

## Overview

Tenrec aims to simplify the MCP experience with IDA Pro. Inspired by the existing IDA Pro plugin ecosystem and 
[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), Tenrec provides a robust framework for building and using 
plugins to automate and enhance reverse engineering tasks with LLMs.

Key features:

- Completely headless IDA Pro interaction, made possible with ida-domain
- Multi-session analysis, great when working with libraries used by an application
- Custom plugin support
- Auto-docs generation (including plugin docs)

Out-of-the box, Tenrec includes the following core plugins:

- **Functions**: Analyze and manage functions, including boundaries, attributes, and pseudocode generation.
- **Cross-References (Xrefs)**: Trace data and code cross-references throughout the binary.
- **Names**: Manage symbol names, demangling, and naming conventions.
- **Comments**: Add and retrieve various types of comments for documentation.
- **Strings**: Search and analyze string literals in the binary.
- **Segments**: Query memory segments and sections.
- **Bytes**: Read and patch binary data at any address.
- **Types**: Manage type information and data structures.
- **Entries**: Access entry points and exported functions.

For a complete breakdown of available plugins and their operations, check out the [documentation](https://axelmierczuk.github.io/tenrec/#/).

## Demo

Using tenrec and Claude Code, we were able to solve Challenge 4 from Flare-On 9 (darn mice) with a single prompt (see below).
Find the complete challenge write-up [here](https://services.google.com/fh/files/misc/04-darn-mice.pdf).


> You have been provided with the binary called darn_mice.exe in the current directory. Use 
tenrec to open a session and reverse the binary. Focus on getting a high-level 
understanding of the application by finding entry points, and tracing execution flow. 
Make sure to rename variables and functions as you work through the binary. The xref 
plugin can be helpful in this task. You will ultimately be looking for a flag. The flag 
is formatted in an email format, and may require decryption. Do not try to guess the 
flag, use your analysis to guide you towards the correct answer based on the binary.


https://github.com/user-attachments/assets/3eb442dd-9b7a-44a6-836b-b73f99f4c2f3


## Installation

### Prerequisites

- Python 3.10 or higher
- IDA Pro 9.1+ installation

### Install with uv 

```bash
uv tool install tenrec
```

Confirm that tenrec is installed:

```bash
# You should see tenrec in the list of installed tools
uv tool list 
# Which tenrec should show the path to the tenrec executable
which tenrec
```

Since tenrec depends on `ida-domain`, you need to set the `IDADIR` environment variable to point to your IDA Pro 
installation directory before running tenrec commands. For example:

```bash
# macOS example
export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"
# Linux example  
export IDADIR="/opt/idapro"  
# Windows example (PowerShell, run as Administrator)
setx IDADIR "C:\Program Files\IDA Pro" /M  
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/axelmierczuk/tenrec.git
cd tenrec

# Install in development mode with dependencies
uv pip install -e ".[dev]"
```

## Usage

### install / uninstall

After installing tenrec, you can install or uninstall the MCP server with a variety of MCP clients.

Currently, the following clients are supported:

- [CLine](https://cline.bot/)
- [Roo Code](https://github.com/RooCodeInc/Roo-Code)
- [Kilo Code](https://kilocode.ai/)
- [Claude](https://claude.ai/download)
- [Cursor](https://cursor.com/en)
- [Windsurf](https://windsurf.com/)
- [Claude Code](https://www.anthropic.com/claude-code)
- [LM Studio](https://lmstudio.ai/)

Get started with the install command:

```bash
tenrec install
```

<details>

<summary><b>Install / uninstall command help menus</b></summary>

```
 Usage: tenrec install [OPTIONS]

 Install tenrec with MCP clients.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --help      Show this message and exit.                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```


```
 Usage: tenrec uninstall [OPTIONS]

 Uninstall tenrec and MCP clients.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --help      Show this message and exit.                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

</details>

### run

Run the tenrec MCP server! 

By default, tenrec loads built-in plugins and ones stored in the config.
If you want to disable loading the config or built-in plugins, use the `--no-config` or `--no-default-plugins` flags.
Additional plugins can be specified with the `-p` / `--plugin` argument.

```bash
tenrec run --transport sse
```

<details>

<summary><b>Run command help menu</b></summary>

```
 Usage: tenrec run [OPTIONS]

 Run the tenrec server.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --no-config                                               If set, the configuration file │
│                                                           will not be used to load       │
│                                                           plugins.                       │
│ --no-default-plugins                                      If set, default plugins will   │
│                                                           not be loaded.                 │
│ --transport           -t  [stdio|http|sse|streamable-htt  Transport type to use for      │
│                           p]                              communication (default: stdio) │
│ --plugin              -p  TEXT                            Plugin to load. Could be a     │
│                                                           PyPI package name, local path, │
│                                                           or git repo.                   │
│ --help                                                    Show this message and exit.    │
╰──────────────────────────────────────────────────────────────────────────────────────────╯

```

</details>

### plugins

Tenrec supports a plugin system that allows you to extend its functionality with custom plugins.

Adding plugins is made simple by specifying a package name that uv can process. For example, this can be a package
that can be found on pypi, a git repo, or on the filesystem. Under the hood, tenrec uses uv to install plugins,
so you can use any format supported by uv ([Astral - Managing Packages](https://docs.astral.sh/uv/pip/packages/#managing-packages)). 

#### Examples

```bash
tenrec plugins add --plugin "example-package"       # Install from PyPI
tenrec plugins add --plugin "/path/to/local/plugin" # Install from local path
tenrec plugins add --plugin \                       # Install from git repo
  "git+ssh://git@github.com/axelmierczuk/tenrec#subdirectory=examples"
```

```bash
# Install from git repo
tenrec plugins add --plugin \
  "git+ssh://git@github.com/axelmierczuk/tenrec#subdirectory=examples"
# List installed plugins
tenrec plugins list
# Remove a plugin by dist name
tenrec plugins remove --dist example_plugin
```

<details>

<summary><b>Plugins command help menus</b></summary>

```
 Usage: tenrec plugins [OPTIONS] COMMAND [ARGS]...

 Manage tenrec plugins.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --help      Show this message and exit.                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────╮
│ add                 Add a new plugin.                                                    │
│ list                List installed plugins.                                              │
│ remove              Remove an existing plugin.                                           │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

```
 Usage: tenrec plugins add [OPTIONS]

 Add a new plugin.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ *  --plugin  -p  TEXT  Plugin to load. Could be a PyPI package name, local path, or git  │
│                        repo.                                                             │
│                        [required]                                                        │
│    --help              Show this message and exit.                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

```
 Usage: tenrec plugins list [OPTIONS]

 List installed plugins.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --help      Show this message and exit.                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

```
 Usage: tenrec plugins remove [OPTIONS]

 Remove an existing plugin.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ *  --dist  -d  TEXT  Plugin dists(s) to remove from the configuration [required]         │
│    --help            Show this message and exit.                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

</details>

### docs

The `docs` command generates documentation for your plugins and operations using [docsify](https://docsify.js.org/). 
This allows you to create self-documenting plugins that are easy to understand and use. 

Using the `-p` / `--plugin` argument, you can specify one or more plugins to include in the documentation. 
Since the server implements session management as core functionality, it will automatically be included in your 
documentation.

Not happy with the default homepage? You can specify a custom README file with the `-r` / `--readme` argument.

```bash
git clone git@github.com:axelmierczuk/tenrec.git
cd tenrec
tenrec docs -p tenrec/plugins/plugins
```

<details>

<summary><b>Docs command help menu</b></summary>

```
 Usage: tenrec docs [OPTIONS]

 Generate documentation.

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│    --output     -o  DIRECTORY  Output directory for the generated documentation.         │
│                                [default: docs]                                           │
│    --readme         PATH       Path to a README file to include in the documentation.    │
│    --base-path      TEXT       The base path for the URL.                                │
│    --repo           TEXT       The URL of the repository for the project.                │
│    --name           TEXT       Name of the documentation set. [default: tenrec]          │
│ *  --plugin     -p  TEXT       Plugin to load. Could be a PyPI package name, local path, │
│                                or git repo.                                              │
│                                [required]                                                │
│    --help                      Show this message and exit.                               │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

</details>

## Creating Custom Plugins

Extend Tenrec with your own plugins!

Simply build a class inheriting from `PluginBase` and define operations.

There are a few important things to note:

- **Name**
  - The `name` attribute must be in `snake_case` format. This name will be pre-pended to all operation names to avoid conflicts.
- **Description**
  - The class docstring will be used as the plugin description in the documentation.
- **Instructions**
  - The `instructions` attribute helps LLMs understand the purpose and usage of your plugin.
- **Operations**
  - Each operation must be decorated with the `@operation()` decorator. You can have other methods in your class, but only decorated methods will be exposed as operations.
  - The docstrings of the operations will be used by the model to understand what the operation does. Be accurate with your parameters and return types.
- **Parameters / Return Types**
  - When working with addresses, use the [`HexEA`](tenrec/plugins/models/ida.py) model if possible. This class ensures that addresses are always 
represented in hexadecimal format, which is more familiar to reverse engineers and the LLMs. It also integrates directly with 
the `ida-domain` database APIs. Import it with:

    ```python
    from tenrec.plugins.models import HexEA
    ```
  - Use standard Python types (e.g., `int`, `str`, `list`, `dict`) or Pydantic models for parameters and return types. 


Once your plugin is defined, create a `pyproject.toml` file to package it, making sure to include:

```toml
[project.entry-points."tenrec.plugins"]
plugin = "file:ClassName" # Specify the path to your plugin class
``` 

A more complex example can be found in [examples](examples).

<details>

<summary><b>Example plugin</b></summary>

```python
from tenrec.plugins.models import PluginBase, Instructions, operation

class CustomAnalysisPlugin(PluginBase):
    """This docstring will be used as the description of your plugin when documenting!"""
    
    name = "must_be_snake_case"
    version = "1.0.0"
    
    # Instructions help LLMs understand the purpose and usage of your plugin
    instructions = Instructions(
        purpose="Perform custom binary analysis operations",
        interaction_style=[
            "You can call operations like find_crypto() or detect_packer() to analyze the binary."
        ],
        examples=[
            "Find cryptographic constants: custom_analysis_find_crypto()",
            "Detect packers: custom_analysis_detect_packer()"
        ],
        anti_examples=[
            "Some anti examples",
        ]
    )
    
    @operation()
    def find_crypto(self) -> list[dict]:
        """Find potential cryptographic constants in the binary."""
        results = []
        # Your analysis logic here using self.database, which is provided to you by PluginBase
        # When switching to a different database/session, this will be updated automatically
        for ea in self.database.functions.get_all():
            # Check for crypto patterns
            pass
        return results
    
    @operation()
    def detect_packer(self) -> dict:
        """Detect if the binary is packed."""
        # Packer detection logic
        return {"packed": False, "packer": None}

```
</details>

### Creating Custom Operation Parameters

If you find yourself needing to add the same arguments to many of your operations, you can define custom operation parameters
(see [tenrec/plugins/models/parameters.py](tenrec/plugins/models/parameters.py) for the implementation details of `PaginatedParameter`).

Custom operations must implement four methods:

- `hook_apply_signature`
- `hook_apply_annotations`
- `hook_pre_call`
- `hook_post_call`

### hook_apply_signature


```python
hook_apply_signature(self, signature: inspect.Signature) -> inspect.Signature
```


The `hook_apply_signature` hook allows for modification of the operation signature. 
You can add or remove parameters, change their types, or modify the return type. In the `PaginatedParameter`, 
we use this hook to add `offset` and `limit` parameters to the operation signature. 

### hook_apply_annotations

```python
hook_apply_annotations(self, annotations: dict) -> dict
```


The `hook_apply_annotations` hook allows for modification of the operation annotations.
In the `PaginatedParameter`, we use this hook to update the return type annotation to reflect the pagination.

### hook_pre_call

```python
hook_pre_call(self, context: dict, *args, **kwargs) -> tuple[tuple, dict]
```

The `hook_pre_call` hook allows for modification of the operation arguments before the call to the operation.
In the `PaginatedParameter`, we use this hook to pop the `offset` and `limit` parameters from the arguments into 
the context that is passed to the operation. 

### hook_post_call

```python
hook_post_call(self, context: dict, result: Any) -> Any
```

The `hook_post_call` hook allows for modification of the operation result after the call to the operation.
In the `PaginatedParameter`, we use this hook to slice the result based on the `offset` and `limit` values from the context.


## Testing

Tenrec includes a comprehensive test suite. Run tests with pytest:

```bash
# Run all tests
IDADIR="/path/to/ida" uv run pytest tenrec/tests/

# Run specific test module
IDADIR="/path/to/ida" uv run pytest tenrec/tests/unit/test_functions_plugin.py

# Run with coverage report
IDADIR="/path/to/ida" uv run pytest tenrec/tests/ --cov=tenrec --cov-report=html

# Run tests with verbose output
IDADIR="/path/to/ida" uv run pytest tenrec/tests/ -v
```

### Writing Tests

Create unit tests for your custom plugins:

```python
import pytest
from unittest.mock import MagicMock
from my_plugins import CustomAnalysisPlugin

class TestCustomAnalysisPlugin:
    @pytest.fixture
    def plugin(self):
        plugin = CustomAnalysisPlugin()
        plugin.db = MagicMock()
        return plugin
    
    def test_find_crypto(self, plugin):
        # Mock IDA database calls
        plugin.db.functions.get_all.return_value = [0x401000, 0x402000]
        
        # Test the operation
        results = plugin.find_crypto()
        assert isinstance(results, list)
```

## Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

We use `ruff` for linting and formatting:

```bash
# Check code style
ruff check .

# Format code
ruff format .

# Fix common issues
ruff check --fix .
```

### Commit Guidelines

- Use clear, descriptive commit messages
- Reference issues when applicable
- Keep commits focused and atomic

## Future Work

- **Enhanced Plugin System**: Dynamic plugin loading and hot-reload support
- **Performance Optimizations**: Caching and batch operations
- **Additional Plugins Ideas**: 
  - Vulnerability detection
  - Binary diffing
  - Automated unpacking
  - Machine learning-based analysis
- **Integration Improvements**: Better integration with other reverse engineering tools
- **Documentation**: Expanded API documentation and tutorials
