# Testing Guide

This guide covers testing patterns for tenrec and custom plugins.

## Running Tests

```bash
# Run all tests
IDADIR="/path/to/ida" uv run pytest tenrec/tests/

# Run specific test module
IDADIR="/path/to/ida" uv run pytest tenrec/tests/unit/test_functions_plugin.py

# Run with coverage report
IDADIR="/path/to/ida" uv run pytest tenrec/tests/ --cov=tenrec --cov-report=html

# Run with verbose output
IDADIR="/path/to/ida" uv run pytest tenrec/tests/ -v

# Run only unit tests (no IDA database required)
IDADIR="/path/to/ida" uv run pytest tenrec/tests/ -m unit
```

## Test Structure

Tests are located in `tenrec/tests/unit/` with one file per plugin:

```
tenrec/tests/
├── conftest.py              # Shared fixtures
└── unit/
    ├── test_functions_plugin.py
    ├── test_xrefs_plugin.py
    ├── test_names_plugin.py
    └── ...
```

## Test Markers

Use markers to categorize tests:

| Marker | Description |
|--------|-------------|
| `@pytest.mark.unit` | Unit tests, no real IDA database required |
| `@pytest.mark.integration` | Integration tests with real IDA databases |
| `@pytest.mark.slow` | Time-intensive tests |
| `@pytest.mark.fixture` | Tests requiring pre-built database fixtures |

## Available Fixtures

### `mock_ida_database`

Complete mock of `ida_domain.Database` with all sub-APIs:

```python
@pytest.fixture
def mock_ida_database() -> Mock:
    db = Mock(spec=Database)

    # Metadata
    db.metadata = DatabaseMetadata(
        path="test_binary.exe",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        base_address=0x400000,
        bitness=64,
        architecture="x86_64",
        format="PE",
    )

    # Functions API
    db.functions = Mock()
    db.functions.get_all = Mock(return_value=[])
    db.functions.get_at = Mock(return_value=None)
    db.functions.get_pseudocode = Mock(return_value=["int main() {", "    return 0;", "}"])

    # Other APIs: xrefs, names, segments, strings, comments, types, bytes, entries
    return db
```

### `mock_database_handler`

Mock `DatabaseHandler` with ready status:

```python
@pytest.fixture
def mock_database_handler(mock_ida_database) -> DatabaseHandler:
    handler = Mock(spec=DatabaseHandler)
    handler.database = mock_ida_database
    handler.status = Status.READY
    handler.is_open = Mock(return_value=True)
    return handler
```

### `mock_function_data`

Sample `FunctionData` object:

```python
@pytest.fixture
def mock_function_data() -> FunctionData:
    return FunctionData(
        start_ea=0x401000,
        end_ea=0x401050,
        name="test_function",
    )
```

### `temp_database_dir`

Temporary directory for test databases:

```python
@pytest.fixture
def temp_database_dir() -> Generator[Path]:
    temp_dir = tempfile.mkdtemp(prefix="ida_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)
```

### `ida_options`

Default IDA command options:

```python
@pytest.fixture
def ida_options() -> IdaCommandOptions:
    return IdaCommandOptions(
        auto_analysis=False,  # Disable for faster tests
        log_file=None,
    )
```

## Writing Plugin Tests

### Basic Pattern

```python
import pytest
from unittest.mock import MagicMock

from tenrec.plugins.plugins.functions import FunctionsPlugin


class TestFunctionsPlugin:
    @pytest.fixture
    def plugin(self, mock_ida_database):
        plugin = FunctionsPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.mark.unit
    def test_get_all_returns_empty_list_when_no_functions(self, plugin):
        plugin.database.functions.get_all.return_value = []
        result = plugin.get_all()
        assert result == []

    @pytest.mark.unit
    def test_get_at_returns_function_data(self, plugin, mock_function_data):
        mock_func_t = MagicMock()
        plugin.database.functions.get_at.return_value = mock_func_t

        with patch.object(FunctionData, 'from_func_t', return_value=mock_function_data):
            result = plugin.get_at(address=0x401000)

        assert result.name == "test_function"
```

### Testing Operations with Side Effects

```python
@pytest.mark.unit
def test_set_name_calls_database(self, plugin):
    plugin.database.functions.set_name.return_value = True

    result = plugin.set_name(address=0x401000, name="new_name")

    plugin.database.functions.set_name.assert_called_once_with(0x401000, "new_name")
    assert result["success"] is True
```

### Testing Paginated Operations

```python
@pytest.mark.unit
def test_get_all_with_pagination(self, plugin, mock_function_data_list):
    plugin.database.functions.get_all.return_value = mock_function_data_list

    # Pagination is handled by the decorator, test the raw return
    result = plugin.get_all()

    assert len(result) == 3
```

## Mocking IDA-specific Types

For operations that transform IDA types:

```python
from unittest.mock import patch, MagicMock

@pytest.mark.unit
def test_transforms_func_t_to_function_data(self, plugin):
    mock_func_t = MagicMock()
    mock_func_t.start_ea = 0x401000
    mock_func_t.end_ea = 0x401050

    plugin.database.functions.get_all.return_value = [mock_func_t]

    expected = FunctionData(start_ea=0x401000, end_ea=0x401050, name="func")
    with patch.object(FunctionData, 'from_func_t', return_value=expected):
        result = plugin.get_all()

    assert result[0].start_ea == 0x401000
```

## Integration Tests

For tests requiring real IDA databases:

```python
@pytest.mark.integration
@pytest.mark.fixture
def test_real_database_operations(self, real_database_handler):
    """Test with actual IDA database (requires fixture)."""
    plugin = FunctionsPlugin()
    plugin.database = real_database_handler.database

    functions = plugin.get_all()
    assert len(functions) > 0
```

Integration tests require:

1. Pre-built database fixtures in `tenrec/tests/fixtures/databases/`
2. `IDADIR` environment variable set
3. Appropriate test markers

## Testing Custom Plugins

```python
import pytest
from unittest.mock import MagicMock

from my_plugin import CryptoAnalysisPlugin


class TestCryptoAnalysisPlugin:
    @pytest.fixture
    def plugin(self, mock_ida_database):
        plugin = CryptoAnalysisPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.mark.unit
    def test_find_constants_returns_list(self, plugin):
        plugin.database.segments.get_all.return_value = []
        result = plugin.find_constants()
        assert isinstance(result, list)

    @pytest.mark.unit
    def test_analyze_function_returns_error_when_not_found(self, plugin):
        plugin.database.functions.get_at.return_value = None
        result = plugin.analyze_function(address=0x401000)
        assert "error" in result
```
