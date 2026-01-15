# Tenrec Development Guide

Tenrec is a headless MCP framework for IDA Pro binary analysis, built with FastMCP and ida-domain.

## Architecture Overview

```
tenrec/
├── server.py                # MCP server, session management
├── sessions.py              # Session wrapper (UUID, DatabaseHandler)
├── plugins/
│   ├── plugin_manager.py    # Plugin dispatch, tool registration
│   ├── plugin_loader.py     # Entry point discovery
│   ├── database_manager.py  # IDA database lifecycle
│   ├── models/
│   │   ├── base.py          # PluginBase, Instructions
│   │   ├── operation.py     # @operation decorator
│   │   ├── parameters.py    # PaginatedParameter, hooks
│   │   └── ida.py           # HexEA, FunctionData models
│   └── plugins/             # 9 built-in plugins
├── management/              # CLI, config, environment
└── tests/unit/              # Unit tests
```

See [agent_docs/architecture.md](agent_docs/architecture.md) for detailed architecture.

## Code Style

Configured in `ruff.toml`:

- **Line length**: 120 characters
- **Python**: 3.13 target
- **Docstrings**: Google style
- **Max complexity**: 10 (mccabe)
- **Max args**: 6, **Max branches**: 12, **Max statements**: 50

```bash
ruff check .       # Lint
ruff format .      # Format
ruff check --fix . # Auto-fix
```

## Plugin Development

Plugins inherit from `PluginBase` and use `@operation()` for MCP tools:

```python
from tenrec.plugins.models import PluginBase, Instructions, operation, HexEA

class MyPlugin(PluginBase):
    name = "my_plugin"           # Must be snake_case
    version = "1.0.0"            # Must be semver
    instructions = Instructions(
        purpose="What this plugin does",
        interaction_style=["How to use it"],
        examples=["my_plugin_operation()"],
        anti_examples=["What NOT to do"],
    )

    @operation()
    def get_data(self, address: HexEA) -> dict:
        """Get data at address."""
        return self.database.functions.get_at(address)
```

Key points:

- `self.database` is injected at runtime (ida-domain Database)
- Use `HexEA` for addresses (ensures hex formatting)
- Docstrings guide LLM understanding
- `PaginatedParameter()` adds offset/limit to list operations

See [agent_docs/plugin-development.md](agent_docs/plugin-development.md) for complete guide.

## Testing

Tests in `tenrec/tests/unit/` use mock fixtures:

```python
class TestMyPlugin:
    @pytest.fixture
    def plugin(self, mock_ida_database):
        plugin = MyPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.mark.unit
    def test_operation(self, plugin):
        result = plugin.get_data(address=0x401000)
        assert result is not None
```

Key fixtures: `mock_ida_database`, `mock_database_handler`, `mock_function_data`

```bash
IDADIR="/path/to/ida" uv run pytest tenrec/tests/ -m unit
```

See [agent_docs/testing.md](agent_docs/testing.md) for patterns.

## Common Tasks

### Add a new plugin operation

1. Add method to plugin class
2. Decorate with `@operation()`
3. Add docstring with `:param` and `:return:`
4. Add unit tests

### Add a new built-in plugin

1. Create `tenrec/plugins/plugins/newplugin.py`
2. Register in `pyproject.toml` entry points:
   ```toml
   [project.entry-points."tenrec.plugins"]
   newplugin = "tenrec.plugins.plugins.newplugin:NewPlugin"
   ```
3. Add to `DEFAULT_PLUGINS` in `__init__.py`
4. Add tests in `tenrec/tests/unit/test_newplugin_plugin.py`

### Run the server locally

```bash
export IDADIR="/path/to/ida"
tenrec run --transport sse
```

## Documentation

- [Architecture](agent_docs/architecture.md) - System design
- [Plugin Development](agent_docs/plugin-development.md) - Creating plugins
- [CLI Reference](agent_docs/cli-reference.md) - Command reference
- [Testing](agent_docs/testing.md) - Test patterns
- [Contributing](agent_docs/contributing.md) - Contribution guidelines
- [Integrations](agent_docs/integrations.md) - MCP client setup
- [Roadmap](agent_docs/roadmap.md) - Future plans
