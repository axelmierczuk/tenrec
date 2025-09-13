"""
Pytest configuration and shared fixtures for IDA MCP server tests.
"""

import shutil
import sys
import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest


# Add tenrec to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from ida_domain.database import Database, DatabaseMetadata, IdaCommandOptions

from tenrec.plugins.database_manager import DatabaseHandler, Status
from tenrec.plugins.models.ida import FunctionData


# ============================================================================
# Mock Data Fixtures
# ============================================================================


@pytest.fixture
def mock_function_data() -> FunctionData:
    """Creates a mock FunctionData object for testing."""
    return FunctionData(
        start_ea=0x401000,
        end_ea=0x401050,
        name="test_function",
    )


@pytest.fixture
def mock_function_data_list() -> list[FunctionData]:
    """Creates a list of mock FunctionData objects."""
    return [
        FunctionData(
            start_ea=0x401000,
            end_ea=0x401050,
            name="main",
        ),
        FunctionData(
            start_ea=0x401100,
            end_ea=0x401200,
            name="helper_func",
        ),
        FunctionData(
            start_ea=0x402000,
            end_ea=0x402010,
            name="printf",
        ),
    ]


# ============================================================================
# Mock IDA Database Fixtures
# ============================================================================


@pytest.fixture
def mock_ida_database() -> Mock:
    """Creates a mock IDA database with common operations."""
    db = Mock(spec=Database)

    # Setup metadata
    db.metadata = DatabaseMetadata(
        path="test_binary.exe",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        base_address=0x400000,
        bitness=64,
        architecture="x86_64",
        format="PE",
    )

    # Setup functions mock
    db.functions = Mock()
    db.functions.get_all = Mock(return_value=[])
    db.functions.get_at = Mock(return_value=None)
    db.functions.get_between = Mock(return_value=[])
    db.functions.get_callees = Mock(return_value=[])
    db.functions.get_callers = Mock(return_value=[])
    db.functions.get_pseudocode = Mock(return_value=["int main() {", "    return 0;", "}"])
    db.functions.get_signature = Mock(return_value="int main(int argc, char **argv)")
    db.functions.set_name = Mock(return_value=True)

    # Setup other plugin mocks
    db.xrefs = Mock()
    db.names = Mock()
    db.segments = Mock()
    db.strings = Mock()
    db.comments = Mock()
    db.types = Mock()
    db.bytes = Mock()
    db.entries = Mock()

    # Setup database state
    db.is_open = Mock(return_value=True)
    db.open = Mock()
    db.close = Mock()

    return db


@pytest.fixture
def mock_database_handler(mock_ida_database) -> DatabaseHandler:
    """Creates a mock DatabaseHandler with a mocked IDA database."""
    handler = Mock(spec=DatabaseHandler)
    handler._database = mock_ida_database
    handler._status = Status.READY
    handler._path = "/tmp/test.idb"
    handler._lock = MagicMock()

    handler.database = mock_ida_database
    handler.is_open = Mock(return_value=True)
    handler.open = Mock()
    handler.close = Mock()
    handler.metadata = Mock(return_value=mock_ida_database.metadata)
    handler.status = Status.READY

    return handler


# ============================================================================
# File System Fixtures
# ============================================================================


@pytest.fixture
def temp_database_dir() -> Generator[Path]:
    """Creates a temporary directory for test databases."""
    temp_dir = tempfile.mkdtemp(prefix="ida_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_database_path() -> Path:
    """Returns path to a test database fixture (if exists)."""
    db_path = Path(__file__).parent / "fixtures" / "databases" / "test_binary.i64"
    if not db_path.exists():
        pytest.skip(f"Test database fixture not found at {db_path}")
    return db_path


@pytest.fixture
def test_binary_path() -> Path:
    """Returns path to a test binary fixture (if exists)."""
    binary_path = Path(__file__).parent / "fixtures" / "binaries" / "test_binary.exe"
    if not binary_path.exists():
        pytest.skip(f"Test binary fixture not found at {binary_path}")
    return binary_path


# ============================================================================
# IDA Command Options Fixtures
# ============================================================================


@pytest.fixture
def ida_options() -> IdaCommandOptions:
    """Creates default IDA command options for testing."""
    return IdaCommandOptions(
        auto_analysis=False,  # Disable for faster tests
        log_file=None,
    )


@pytest.fixture
def ida_options_with_analysis() -> IdaCommandOptions:
    """Creates IDA command options with analysis enabled."""
    return IdaCommandOptions(auto_analysis=True, log_file=None)


# ============================================================================
# Integration Test Fixtures
# ============================================================================


@pytest.fixture
def real_database_handler(test_database_path, ida_options) -> Generator[DatabaseHandler]:
    """Creates a real DatabaseHandler with an actual IDA database (for integration tests)."""
    handler = DatabaseHandler(str(test_database_path), ida_options)
    handler.open(analyze=False)
    yield handler
    handler.close()


# ============================================================================
# Plugin Fixtures
# ============================================================================


@pytest.fixture
def mock_plugin_base():
    """Base fixture for creating mock plugins."""
    from tenrec.plugins.models.base import PluginBase

    class MockPlugin(PluginBase):
        name = "mock_plugin"

        def __init__(self, database):
            self._database = database

    return MockPlugin


# ============================================================================
# Test Markers
# ============================================================================


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests that don't require IDA databases")
    config.addinivalue_line("markers", "integration: Integration tests with real IDA databases")
    config.addinivalue_line("markers", "slow: Tests that take a long time to run")
    config.addinivalue_line("markers", "fixture: Tests that require pre-built database fixtures")
