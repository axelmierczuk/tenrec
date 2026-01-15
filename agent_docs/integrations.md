# MCP Client Integrations

Guide for integrating tenrec with various MCP clients.

## Supported Clients (Auto-Install)

The `tenrec install` command automatically configures these clients:

| Client | Website |
|--------|---------|
| CLine | https://cline.bot/ |
| Roo Code | https://github.com/RooCodeInc/Roo-Code |
| Kilo Code | https://kilocode.ai/ |
| Claude Desktop | https://claude.ai/download |
| Cursor | https://cursor.com/ |
| Windsurf | https://windsurf.com/ |
| Claude Code | https://anthropic.com/claude-code |
| LM Studio | https://lmstudio.ai/ |

```bash
tenrec install
```

The installer will prompt you to select which clients to configure.

## Manual Integration

For clients not yet supported by the installer, configure manually.

### Generic MCP Configuration

Most MCP clients use a JSON configuration file. Add tenrec as a server:

```json
{
  "mcpServers": {
    "tenrec": {
      "command": "uvx",
      "args": ["tenrec", "run"],
      "env": {
        "IDADIR": "/path/to/ida"
      }
    }
  }
}
```

### Configuration Locations

| Client | Config Path |
|--------|-------------|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code | `~/.claude.json` or project `.claude.json` |
| Cursor | `.cursor/mcp.json` in project |
| Windsurf | `.windsurf/mcp.json` in project |

## Codex Integration

OpenAI Codex requires manual configuration.

### Prerequisites

- Codex CLI installed (https://github.com/openai/codex/releases)
- Azure OpenAI or OpenAI API key
- tenrec installed (`uv tool install tenrec`)

### Configuration

Create `~/.codex/config.toml`:

```toml
# Model configuration
model = "gpt-4.1"
model_provider = "azure"
preferred_auth_method = "apikey"

# Azure provider settings
[model_providers.azure]
name = "Azure"
base_url = "https://<your_deployment>.openai.azure.com/openai"
env_key = "AZURE_OPENAI_API_KEY"
query_params = { api-version = "2025-04-01-preview" }
wire_api = "responses"
model_reasoning_effort = "high"

# Trust configuration
[projects."/tmp"]
trust_level = "trusted"

# Tenrec MCP server
[mcp_servers.tenrec]
command = "uvx"
args = ["tenrec", "run"]
env = { "IDADIR" = "/path/to/ida" }
```

### Environment Setup

```bash
# Set API key (Azure example)
export AZURE_OPENAI_API_KEY="your-api-key-here"

# Or for OpenAI
export OPENAI_API_KEY="your-api-key-here"
```

### Testing

```bash
# Verify Codex setup
codex "Write me a Haiku"

# Test with tenrec
codex "Use tenrec to open a session on /path/to/binary.exe and list functions"
```

### Azure OpenAI Notes

- Use a supported region for the [Responses API](https://learn.microsoft.com/en-us/azure/ai-foundry/openai/how-to/responses)
- Deploy GPT-4.1 or compatible model in your workspace
- API keys are found in Azure AI Foundry Overview page

## Transport Options

Tenrec supports multiple transports:

| Transport | Flag | Use Case |
|-----------|------|----------|
| stdio | `--transport stdio` | Default, most clients |
| http | `--transport http` | REST integration |
| sse | `--transport sse` | Server-sent events |
| streamable-http | `--transport streamable-http` | Large responses |

Example with SSE:

```json
{
  "mcpServers": {
    "tenrec": {
      "command": "uvx",
      "args": ["tenrec", "run", "--transport", "sse"],
      "env": {
        "IDADIR": "/path/to/ida"
      }
    }
  }
}
```

## Troubleshooting

### Common Issues

**"IDADIR not set"**
- Ensure `IDADIR` environment variable points to IDA installation
- In config files, set it in the `env` section

**"Permission denied"**
- Check file permissions on IDA installation
- Verify tenrec is installed correctly: `which tenrec`

**"Plugin not found"**
- Verify plugin is installed: `tenrec plugins list`
- Check entry points in plugin's `pyproject.toml`

### Debug Mode

Enable debug logging:

```bash
export TENREC_DEBUG=1
tenrec run
```

Or in config:

```json
{
  "mcpServers": {
    "tenrec": {
      "command": "uvx",
      "args": ["tenrec", "run"],
      "env": {
        "IDADIR": "/path/to/ida",
        "TENREC_DEBUG": "1"
      }
    }
  }
}
```
