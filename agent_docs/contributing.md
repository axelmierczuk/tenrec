# Contributing to Tenrec

Guidelines for contributing to the tenrec project.

## Development Setup

### Prerequisites

- Python 3.10 or higher
- IDA Pro 9.1+ installation
- `uv` package manager

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/axelmierczuk/tenrec.git
cd tenrec

# Install in development mode with dependencies
uv pip install -e ".[dev]"
```

### Set Environment

```bash
# Set IDA directory (required)
export IDADIR="/path/to/ida"
```

## Code Style

Tenrec uses `ruff` for linting and formatting. Configuration is in `ruff.toml`.

### Key Settings

| Setting | Value |
|---------|-------|
| Line length | 120 characters |
| Target Python | 3.13 |
| Docstring style | Google |
| Max complexity | 10 (mccabe) |
| Max function args | 6 |
| Max branches | 12 |
| Max statements | 50 |

### Running Linters

```bash
# Check code style
ruff check .

# Format code
ruff format .

# Fix common issues
ruff check --fix .
```

### Type Annotations

- All public functions should have type annotations
- Use modern syntax: `list[T]`, `dict[K, V]`, `X | Y` for unions
- Import types from `typing` only when necessary

## Pull Request Process

### 1. Fork and Branch

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/tenrec.git

# Create a feature branch
git checkout -b feature/amazing-feature
```

### 2. Make Changes

- Write clear, focused commits
- Follow the code style guidelines
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run linters
ruff check .
ruff format --check .

# Run tests
IDADIR="/path/to/ida" uv run pytest tenrec/tests/ -m unit
```

### 4. Submit PR

```bash
# Push to your fork
git push origin feature/amazing-feature

# Open a Pull Request on GitHub
```

### PR Guidelines

- Use clear, descriptive titles
- Reference related issues (e.g., "Fixes #123")
- Include a description of changes
- Keep PRs focused on a single feature/fix

## Commit Guidelines

### Message Format

```
<type>: <short description>

<optional body with more details>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

### Examples

```
feat: Add crypto detection plugin

Implements detection of common cryptographic constants
and patterns in analyzed binaries.

Closes #42
```

```
fix: Handle missing function in xrefs plugin

Return empty list instead of raising exception when
function is not found at specified address.
```

## Adding New Plugins

### Built-in Plugins

1. Create `tenrec/plugins/plugins/newplugin.py`
2. Inherit from `PluginBase`, implement operations
3. Register in `pyproject.toml` entry points:

```toml
[project.entry-points."tenrec.plugins"]
newplugin = "tenrec.plugins.plugins.newplugin:NewPlugin"
```

4. Add to `DEFAULT_PLUGINS` in `tenrec/plugins/plugins/__init__.py`
5. Add unit tests in `tenrec/tests/unit/test_newplugin_plugin.py`

### External Plugins

See [Plugin Development Guide](plugin-development.md) for creating standalone plugins.

## Testing Requirements

- All new features must include tests
- Unit tests should use mocks (no real IDA database)
- Use `@pytest.mark.unit` for unit tests
- Aim for >80% coverage on new code

## Documentation

- Update `README.md` for user-facing changes
- Update `agent_docs/` for developer documentation
- Add docstrings to new public functions
- Use Google-style docstring format

## Getting Help

- Open an issue for bugs or feature requests
- Use discussions for questions
- Check existing issues before creating new ones
