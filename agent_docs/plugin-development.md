# Plugin Development Guide

This guide covers creating custom plugins for tenrec.

## Quick Start

A minimal plugin requires:

1. Inherit from `PluginBase`
2. Define `name` (snake_case), `version` (semver), and `instructions`
3. Decorate methods with `@operation()`

```python
from tenrec.plugins.models import PluginBase, Instructions, operation

class MyPlugin(PluginBase):
    """Plugin description for documentation."""

    name = "my_plugin"
    version = "1.0.0"
    instructions = Instructions(
        purpose="What this plugin does",
        interaction_style=["How to use it effectively"],
        examples=["my_plugin_operation_name()"],
        anti_examples=["What NOT to do"],
    )

    @operation()
    def operation_name(self) -> dict:
        """Operation description for the LLM."""
        # Access IDA database via self.database
        return {"result": "value"}
```

## Plugin Structure

### Required Attributes

| Attribute | Type | Validation |
|-----------|------|------------|
| `name` | `str` | Must be snake_case, valid Python identifier |
| `version` | `str` | Must be semver format (X.Y.Z) |
| `instructions` | `Instructions` | Guides LLM usage |

### The `Instructions` Model

```python
class Instructions(BaseModel):
    purpose: str              # What the plugin does
    interaction_style: list[str]  # How to use effectively
    examples: list[str]       # Example usage
    anti_examples: list[str]  # What NOT to do
```

### The `@operation()` Decorator

Marks methods as MCP-exposed tools:

```python
@operation()
def get_data(self, address: int) -> list[dict]:
    """Get data at address.

    :param address: Memory address to query
    :return: List of data items
    """
    ...
```

Decorator options:

- `options`: List of `OperationParameterBase` instances (e.g., `PaginatedParameter`)
- `unsafe`: Boolean flag for potentially destructive operations

## Working with Addresses

Use `HexEA` model for addresses - ensures hex formatting familiar to reverse engineers:

```python
from tenrec.plugins.models import HexEA

@operation()
def get_function(self, address: HexEA) -> dict:
    # address is automatically validated and formatted
    func = self.database.functions.get_at(address)
    return {"name": func.name, "start": str(address)}
```

## Accessing the IDA Database

Plugins receive `self.database` (an `ida_domain.Database` instance) at runtime:

```python
@operation()
def list_functions(self) -> list[dict]:
    functions = []
    for func in self.database.functions.get_all():
        functions.append({
            "name": func.name,
            "start": hex(func.start_ea),
            "end": hex(func.end_ea),
        })
    return functions
```

Common database APIs:

- `self.database.functions` - Function queries
- `self.database.xrefs` - Cross-references
- `self.database.names` - Symbol names
- `self.database.segments` - Memory segments
- `self.database.strings` - String literals
- `self.database.comments` - Comments
- `self.database.types` - Type information
- `self.database.bytes` - Raw bytes
- `self.database.entries` - Entry points

## Custom Operation Parameters

For reusable parameter patterns across operations, implement `OperationParameterBase`:

```python
from tenrec.plugins.models.parameters import OperationParameterBase

class MyCustomParameter(OperationParameterBase):
    name = "my_parameter"

    def hook_apply_signature(self, signature):
        """Add parameters to the function signature."""
        # Add new parameters
        return modified_signature

    def hook_apply_annotations(self, annotations):
        """Update type annotations."""
        return modified_annotations

    def hook_pre_call(self, context, *args, **kwargs):
        """Process arguments before the operation call."""
        # Extract custom args, store in context
        return args, kwargs

    def hook_post_call(self, context, result):
        """Process result after the operation call."""
        # Transform result based on context
        return modified_result
```

### Built-in: `PaginatedParameter`

Adds `offset` and `limit` parameters for paginating list results:

```python
from tenrec.plugins.models.parameters import PaginatedParameter

@operation(options=[PaginatedParameter(default_offset=0, default_limit=100)])
def get_all_strings(self) -> list[dict]:
    """Returns paginated string results."""
    return self.database.strings.get_all()
```

Response format:

```json
{
  "total": 1500,
  "offset": 0,
  "limit": 100,
  "data": [...]
}
```

## Packaging Your Plugin

### pyproject.toml Structure

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "my-tenrec-plugin"
version = "1.0.0"
dependencies = ["tenrec"]

[project.entry-points."tenrec.plugins"]
my_plugin = "my_package.plugins:MyPlugin"
```

The entry point format is: `plugin_name = "module.path:ClassName"`

### Installation Methods

```bash
# From PyPI
tenrec plugins add --plugin "my-tenrec-plugin"

# From git repo
tenrec plugins add --plugin "git+https://github.com/user/repo"

# From local path
tenrec plugins add --plugin "/path/to/plugin"
```

## Best Practices

1. **Clear docstrings**: LLMs use docstrings to understand operations
2. **Type annotations**: Always annotate parameters and return types
3. **Use `HexEA`**: For address parameters, ensures consistent hex formatting
4. **Descriptive `Instructions`**: Guide LLMs on when/how to use your plugin
5. **Return dicts/lists**: Avoid returning raw IDA objects
6. **Handle missing data**: Return `None` or empty results gracefully

## Example: Complete Plugin

```python
from tenrec.plugins.models import PluginBase, Instructions, operation, HexEA
from tenrec.plugins.models.parameters import PaginatedParameter


class CryptoAnalysisPlugin(PluginBase):
    """Analyze cryptographic patterns in binaries."""

    name = "crypto_analysis"
    version = "1.0.0"
    instructions = Instructions(
        purpose="Detect and analyze cryptographic constants and patterns",
        interaction_style=[
            "Use find_constants() first to locate crypto patterns",
            "Then use analyze_function() on suspicious functions",
        ],
        examples=[
            "crypto_analysis_find_constants()",
            "crypto_analysis_analyze_function(address=0x401000)",
        ],
        anti_examples=[
            "Don't call analyze_function without finding constants first",
        ],
    )

    CRYPTO_CONSTANTS = {
        0x67452301: "MD5/SHA-1 init",
        0xEFCDAB89: "MD5/SHA-1 init",
        # ... more constants
    }

    @operation(options=[PaginatedParameter()])
    def find_constants(self) -> list[dict]:
        """Find known cryptographic constants in the binary.

        :return: List of found constants with locations
        """
        results = []
        for segment in self.database.segments.get_all():
            # Search logic here
            pass
        return results

    @operation()
    def analyze_function(self, address: HexEA) -> dict:
        """Analyze a function for cryptographic patterns.

        :param address: Function address to analyze
        :return: Analysis results including detected algorithms
        """
        func = self.database.functions.get_at(address)
        if not func:
            return {"error": "Function not found"}

        pseudocode = self.database.functions.get_pseudocode(address)
        # Analysis logic here

        return {
            "function": func.name,
            "address": str(address),
            "algorithms": [],
            "confidence": 0.0,
        }
```
