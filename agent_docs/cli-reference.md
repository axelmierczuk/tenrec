# CLI Reference

Complete reference for all tenrec CLI commands.

## Global Options

All commands support:

- `--help`: Show help message and exit

## tenrec install

Install tenrec with MCP clients.

```
Usage: tenrec install [OPTIONS]

Install tenrec with MCP clients.

Options:
  --help    Show this message and exit.
```

Supported clients:

- CLine
- Roo Code
- Kilo Code
- Claude Desktop
- Cursor
- Windsurf
- Claude Code
- LM Studio

The installer will prompt you to select which clients to configure.

## tenrec uninstall

Remove tenrec from MCP clients.

```
Usage: tenrec uninstall [OPTIONS]

Uninstall tenrec and MCP clients.

Options:
  --help    Show this message and exit.
```

## tenrec run

Start the tenrec MCP server.

```
Usage: tenrec run [OPTIONS]

Run the tenrec server.

Options:
  --no-config                        Do not load plugins from configuration file
  --no-default-plugins               Do not load built-in plugins
  -t, --transport [stdio|http|sse|streamable-http]
                                     Transport type (default: stdio)
  -p, --plugin TEXT                  Additional plugin to load (repeatable)
  --help                             Show this message and exit.
```

### Transport Options

| Transport | Description | Use Case |
|-----------|-------------|----------|
| `stdio` | Standard input/output | Default for most MCP clients |
| `http` | HTTP server | REST-style integration |
| `sse` | Server-sent events | Real-time streaming |
| `streamable-http` | Streamable HTTP | Large response streaming |

### Examples

```bash
# Run with default settings (stdio transport, all plugins)
tenrec run

# Run with SSE transport
tenrec run --transport sse

# Run without built-in plugins
tenrec run --no-default-plugins

# Load additional plugin from PyPI
tenrec run --plugin "tenrec-crypto-plugin"

# Load plugin from local path
tenrec run --plugin "/path/to/my/plugin"

# Load plugin from git repo
tenrec run --plugin "git+https://github.com/user/plugin"

# Combine options
tenrec run -t sse -p "plugin1" -p "plugin2" --no-config
```

## tenrec plugins

Manage tenrec plugins.

```
Usage: tenrec plugins [OPTIONS] COMMAND [ARGS]...

Manage tenrec plugins.

Options:
  --help    Show this message and exit.

Commands:
  add       Add a new plugin.
  list      List installed plugins.
  remove    Remove an existing plugin.
```

### tenrec plugins add

Add a plugin to the configuration.

```
Usage: tenrec plugins add [OPTIONS]

Add a new plugin.

Options:
  -p, --plugin TEXT    Plugin to load (PyPI, local path, or git repo) [required]
  --help               Show this message and exit.
```

Plugin sources:

- **PyPI**: Package name (e.g., `tenrec-crypto-plugin`)
- **Local path**: Absolute or relative path (e.g., `/path/to/plugin`)
- **Git repo**: Git URL (e.g., `git+https://github.com/user/repo`)
  - With subdirectory: `git+https://github.com/user/repo#subdirectory=plugins/myplugin`

### tenrec plugins list

Show configured plugins.

```
Usage: tenrec plugins list [OPTIONS]

List installed plugins.

Options:
  --help    Show this message and exit.
```

### tenrec plugins remove

Remove a plugin from configuration.

```
Usage: tenrec plugins remove [OPTIONS]

Remove an existing plugin.

Options:
  -d, --dist TEXT    Plugin distribution name(s) to remove [required]
  --help             Show this message and exit.
```

### Examples

```bash
# Add plugin from PyPI
tenrec plugins add --plugin "example-package"

# Add plugin from local path
tenrec plugins add --plugin "/path/to/local/plugin"

# Add plugin from git repo with subdirectory
tenrec plugins add --plugin \
  "git+ssh://git@github.com/axelmierczuk/tenrec#subdirectory=examples"

# List all configured plugins
tenrec plugins list

# Remove a plugin by distribution name
tenrec plugins remove --dist example_plugin
```

## tenrec docs

Generate documentation for plugins.

```
Usage: tenrec docs [OPTIONS]

Generate documentation.

Options:
  -o, --output DIRECTORY    Output directory (default: docs)
  --readme PATH             Custom README file for homepage
  --base-path TEXT          Base path for URLs
  --repo TEXT               Repository URL for project
  --name TEXT               Documentation name (default: tenrec)
  -p, --plugin TEXT         Plugin to document [required]
  --help                    Show this message and exit.
```

Documentation is generated using [Docsify](https://docsify.js.org/) and includes:

- Plugin descriptions
- Operation signatures and docstrings
- Instructions for LLM usage
- Session management tools

### Examples

```bash
# Generate docs for built-in plugins
tenrec docs -p tenrec/plugins/plugins

# Generate docs with custom output directory
tenrec docs -p my_plugin -o ./documentation

# Generate docs with custom README
tenrec docs -p my_plugin --readme ./CUSTOM_README.md

# Generate docs for multiple plugins
tenrec docs -p plugin1 -p plugin2 -p plugin3
```

## Environment Variables

### IDADIR (Required)

Path to IDA Pro installation directory.

```bash
# macOS
export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS"

# Linux
export IDADIR="/opt/idapro"

# Windows (PowerShell, run as Administrator)
setx IDADIR "C:\Program Files\IDA Pro" /M
```

### TENREC_DEBUG (Optional)

Enable debug logging.

```bash
export TENREC_DEBUG=1
```
