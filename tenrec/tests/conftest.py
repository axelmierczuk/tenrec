"""
Pytest configuration and shared fixtures for IDA MCP server tests.
"""

import shutil
import subprocess
import sys
import tempfile
import time
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
    db.functions.get_signature = Mock(return_value="int main(int argc, char **argv)")
    db.functions.set_name = Mock(return_value=True)
    db.functions.does_return = Mock(return_value=True)
    db.functions.get_disassembly = Mock(return_value=["mov eax, 0", "ret"])
    db.functions.get_flags = Mock(return_value=0)
    db.functions.get_local_variables = Mock(return_value=[])
    db.functions.get_local_variable_by_name = Mock(return_value=None)
    db.functions.get_local_variable_references = Mock(return_value=[])
    db.functions.get_data_items = Mock(return_value=[])

    # Setup pseudocode mock
    db.pseudocode = Mock()
    db.pseudocode.get_text = Mock(return_value=["int main() {", "    return 0;", "}"])
    db.pseudocode.decompile_many = Mock(return_value=[])

    # Setup other plugin mocks
    db.xrefs = Mock()
    db.names = Mock()
    db.segments = Mock()
    db.strings = Mock()
    db.comments = Mock()
    db.types = Mock()
    db.bytes = Mock()
    db.entries = Mock()
    db.imports = Mock()
    db.imports.get_all_imports = Mock(return_value=[])
    db.imports.get_all_modules = Mock(return_value=[])
    db.imports.get_import_at = Mock(return_value=None)
    db.imports.get_import_by_name = Mock(return_value=None)
    db.imports.get_module_by_name = Mock(return_value=None)
    db.imports.get_imports_for_module = Mock(return_value=[])
    db.imports.get_module_count = Mock(return_value=0)
    db.imports.get_import_count = Mock(return_value=0)

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


FIXTURES_DIR = Path(__file__).parent / "fixtures"
FIXTURE_DATABASES_DIR = FIXTURES_DIR / "databases"


def fixture_database_path(name: str) -> Path:
    """Locate a built fixture database by target name.

    Skips the calling test if the fixture has not been built yet (run
    ``python tenrec/tests/fixtures/build_fixtures.py`` to produce it).
    """
    db_path = FIXTURE_DATABASES_DIR / f"{name}.i64"
    if not db_path.exists():
        pytest.skip(
            f"Fixture database '{name}.i64' not found. Run "
            f"'python tenrec/tests/fixtures/build_fixtures.py' to build it."
        )
    return db_path


def _make_db_fixture(target_name: str):
    """Create a function-scoped fixture that yields an opened ``Database``.

    Each fixture opens the on-disk ``.i64`` with ``save_on_close=False`` so
    write-tests (set_name, set_comment, declare_c_type, ...) can mutate the
    in-memory database freely without persisting changes back to the file.
    Combined with the ``restore_*`` helpers, this gives us write-test
    isolation for free across the entire integration suite.
    """

    @pytest.fixture
    def db_fixture(ida_options) -> Generator[Database]:
        path = fixture_database_path(target_name)
        db = Database()
        db.open(str(path), ida_options, save_on_close=False)
        try:
            yield db
        finally:
            db.close(save=False)

    db_fixture.__name__ = f"{target_name}_db"
    return db_fixture


basic_db = _make_db_fixture("basic")
types_zoo_db = _make_db_fixture("types_zoo")
data_layout_db = _make_db_fixture("data_layout")
linux_debugger_db = _make_db_fixture("linux_debugger")
windows_debugger_db = _make_db_fixture("windows_debugger")


# ============================================================================
# Docker-backed live-debugger fixtures
# ============================================================================
#
# The gdbserver-in-container path is the canonical headless live-debugger
# environment for tenrec — IDA can attach to a remote process over
# gdb-remote from any host platform without entitlement gymnastics. The
# fixture images are built by build_fixtures.py and each contain a small
# binary plus gdbserver pre-launching it.
#
# Two variants:
#   * tenrec-fixture-linux_debugger — Linux ELF, runs on any docker daemon
#   * tenrec-fixture-windows_debugger — Windows PE, only runs on a docker
#     daemon in Windows-container mode (Windows host required)


def _docker_available() -> bool:
    """Return True if the docker CLI is on PATH and the daemon is reachable."""
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    return True


def _docker_os_type() -> str | None:
    """Return the daemon's container OS type ("linux" / "windows"), or None."""
    if not _docker_available():
        return None
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None


def _docker_image_exists(tag: str) -> bool:
    """Return True if a local docker image with ``tag`` is present."""
    result = subprocess.run(
        ["docker", "image", "inspect", tag],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _free_tcp_port() -> int:
    """Bind to port 0, learn the assigned port, release it for the caller."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_listener(host: str, port: int, timeout: float = 10.0) -> None:
    """Block until ``host:port`` accepts a TCP connection or fail.

    Windows containers cold-start much slower than Linux ones (the OS
    image takes seconds to spin up the user process), so callers can
    extend the timeout for that path.
    """
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    msg = f"Container never listened on {host}:{port}"
    raise RuntimeError(msg)


def _spawn_gdbserver_container(
    image: str, required_os: str, listen_timeout: float
) -> Generator[tuple[str, int]]:
    """Shared lifecycle for a fixture container that publishes gdbserver.

    All variants follow the same pattern: pick a free TCP port, run the
    image with `-p host_port:31337`, wait until the listener is up, hand
    `(host, port)` to the test, and tear the container down on exit.
    The only thing that changes between Linux and Windows is the image
    tag and the required daemon OS — factored out so adding a third
    platform stays a one-liner.
    """
    if not _docker_available():
        pytest.skip("Docker daemon unreachable; install Docker / start colima.")
    daemon_os = _docker_os_type()
    if daemon_os != required_os:
        pytest.skip(
            f"Image {image!r} requires docker OSType={required_os!r}, "
            f"daemon reports {daemon_os!r}. Run on a host with a matching "
            "container runtime (Windows host for Windows containers)."
        )
    if not _docker_image_exists(image):
        pytest.skip(
            f"Docker image {image!r} not present. Run "
            "'python tenrec/tests/fixtures/build_fixtures.py' on a host "
            f"with docker OSType={required_os!r} to build it."
        )

    host = "127.0.0.1"
    port = _free_tcp_port()
    name = f"tenrec-gdbserver-{port}"

    # Defensive cleanup against a stuck leftover from a prior failed run.
    subprocess.run(
        ["docker", "rm", "-f", name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.check_call(
        [
            "docker", "run", "-d", "--rm",
            "--name", name,
            "-p", f"{host}:{port}:31337",
            image,
        ],
        stdout=subprocess.DEVNULL,
    )
    try:
        _wait_for_listener(host, port, timeout=listen_timeout)
        yield host, port
    finally:
        subprocess.run(
            ["docker", "rm", "-f", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


@pytest.fixture
def gdbserver_container() -> Generator[tuple[str, int]]:
    """Spawn the Linux fixture under gdbserver in Docker; yield ``(host, port)``."""
    yield from _spawn_gdbserver_container(
        image="tenrec-fixture-linux_debugger",
        required_os="linux",
        listen_timeout=10.0,
    )


@pytest.fixture
def gdbserver_windows_container() -> Generator[tuple[str, int]]:
    """Spawn the Windows fixture under gdbserver in Docker; yield ``(host, port)``.

    Skips on any host where the docker daemon isn't running Windows
    containers — Linux daemons can't launch the ``windows/servercore``
    base image. The cold-start budget is bigger here than for Linux:
    Windows containers commonly take 5–15s before user code is reachable.
    """
    yield from _spawn_gdbserver_container(
        image="tenrec-fixture-windows_debugger",
        required_os="windows",
        listen_timeout=60.0,
    )


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


# Markers are now declared in pytest.ini.
