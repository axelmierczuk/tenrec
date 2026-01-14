# Tenrec Architecture

This document describes the internal architecture of tenrec, a headless MCP framework for IDA Pro binary analysis.

## System Overview

Tenrec bridges IDA Pro's binary analysis capabilities with AI/LLM workflows through the Model Context Protocol (MCP). The system operates entirely headless using the `ida-domain` SDK.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  MCP Client │────▶│ Tenrec Server│────▶│  IDA Domain │
│ (Claude, etc)│◀────│  (FastMCP)   │◀────│  (Headless) │
└─────────────┘     └──────────────┘     └─────────────┘
        │                  │
        │                  ▼
        │           ┌──────────────┐
        │           │   Plugins    │
        │           │ (9 built-in) │
        │           └──────────────┘
        │                  │
        └──────────────────┘
              MCP Tools
```

## Core Components

### Server (`tenrec/server.py`)

The central orchestrator that:

- Manages multiple IDA Pro sessions (dict of `Session` objects)
- Coordinates plugin registration with FastMCP
- Exposes session operations: `new_session()`, `list_sessions()`, `set_session()`, `remove_session()`, `remove_all_sessions()`
- Applies IDA monkey patches for compatibility (e.g., `StringType.__str__`)

### Session (`tenrec/sessions.py`)

Session wrapper that:

- Uniquely identified by UUID
- Wraps `DatabaseHandler` for each binary
- Tracks file path, IDA options, and database status

### DatabaseHandler (`tenrec/plugins/database_manager.py`)

Thread-safe database lifecycle manager:

- Wraps `ida_domain.Database`
- Manages open/close with proper analysis flags
- Tracks status: `WAITING → OPENING → READY → CLOSING → CLOSED`
- Handles save/load of IDA database files (`.i64`, `.idb`)

### Plugin System

#### PluginBase (`tenrec/plugins/models/base.py`)

Abstract base class for all plugins:

```python
class PluginBase:
    database: Database  # Injected at runtime
    name: str           # Must be snake_case
    version: str        # Must be semver (X.Y.Z)
    instructions: Instructions
```

Validation is enforced in `__new__`:
- `name` must be a valid snake_case identifier
- `version` must follow semantic versioning

#### Operation Decorator (`tenrec/plugins/models/operation.py`)

Marks methods as MCP-exposed tools:

```python
@operation(options=[PaginatedParameter()])
def get_all_functions(self) -> list[FunctionData]:
    ...
```

- Attached to plugin methods
- Supports custom parameter options (e.g., `PaginatedParameter`)
- Transforms signatures/return types for MCP compatibility

#### PluginManager (`tenrec/plugins/plugin_manager.py`)

Central dispatcher that:

- Introspects plugins for `@operation()` decorated methods
- Creates MCP-compatible tool wrappers via dispatcher pattern
- Injects database references into plugin instances
- Handles pre/post-call hooks for custom operation parameters
- Returns standardized error dicts on exceptions: `{"exception": type(e).__name__, "value": str(e)}`

#### PluginLoader (`tenrec/plugins/plugin_loader.py`)

Dynamic plugin discovery:

- Uses setuptools entry points: `tenrec.plugins` group
- Supports loading from PyPI, git repos, or local paths

## Directory Structure

```
tenrec/
├── __main__.py              # Entry point, logger config
├── entrypoint.py            # CLI setup (rich-click)
├── server.py                # Main MCP server, session management
├── sessions.py              # Session class
├── plugins/
│   ├── plugin_manager.py    # Discovers & dispatches plugin operations
│   ├── plugin_loader.py     # Entry point discovery
│   ├── database_manager.py  # IDA database lifecycle
│   ├── models/
│   │   ├── base.py          # PluginBase class with validation
│   │   ├── exceptions.py    # OperationError
│   │   ├── operation.py     # @operation decorator
│   │   ├── parameters.py    # PaginatedParameter & parameter hooks
│   │   └── ida.py           # IDA data models (HexEA, FunctionData)
│   └── plugins/             # Built-in plugins (9)
│       ├── functions.py
│       ├── xrefs.py
│       ├── names.py
│       ├── comments.py
│       ├── strings.py
│       ├── segments.py
│       ├── bytes.py
│       ├── types.py
│       └── entries.py
├── management/              # CLI and configuration
│   ├── environment.py       # Environment variable handling
│   ├── config.py            # Plugin configuration management
│   ├── venv.py              # Virtual environment management
│   └── options.py           # CLI option decorators
├── documentation/           # Auto-doc generation (Docsify)
└── tests/
    └── unit/                # Unit tests
```

## Data Flow

1. **Client Connection**: MCP client connects via configured transport (stdio, HTTP, SSE, streamable-HTTP)
2. **Session Creation**: Client calls `new_session(path)` to open an IDA database
3. **Tool Invocation**: Client calls plugin operation (e.g., `functions_get_all`)
4. **Plugin Dispatch**: PluginManager routes to appropriate plugin method
5. **Database Access**: Plugin uses `self.database` (ida-domain) to query IDA
6. **Result Return**: Results serialized and returned via MCP

## Built-in Plugins

| Plugin | Purpose |
|--------|---------|
| `functions` | Function analysis, pseudocode, boundaries |
| `xrefs` | Data/code cross-references |
| `names` | Symbol naming, demangling, renaming |
| `comments` | Code comments (regular, repeatable, etc.) |
| `strings` | String literal search/analysis |
| `segments` | Memory segment queries |
| `bytes` | Binary data read/patch |
| `types` | Type information & data structures |
| `entries` | Entry points & exported functions |

## Session Management

- Each binary gets a unique UUID session
- Only one session can be "active" at a time
- Previous session auto-closed when switching
- Supports concurrent database management via threading

## MCP Integration

- FastMCP server exposes all plugin operations as tools
- Tool naming convention: `{plugin_name}_{method_name}`
- Instructions auto-generated from plugin `Instructions` model
- Supports multiple transports: stdio, HTTP, SSE, streamable-HTTP
