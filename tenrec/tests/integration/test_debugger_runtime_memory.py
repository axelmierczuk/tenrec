"""Live-debugger integration tests: read uninitialised globals at runtime.

The contract under test: ``read_memory()`` proxies
``ida_idd.dbg_read_memory()``, which returns the *runtime* memory of the
debugged process — not the static IDA database view. For a global that's
defined but not initialised in C source, the OS zero-fills the BSS page
at process start; runtime memory is REAL memory. After a function writes
to the global, the runtime read must see the new value.

The same contract is exercised against:

  * Linux ELF + gdbserver (image: ``tenrec-fixture-linux_debugger``) —
    runs on any host with a Linux docker daemon.
  * Windows PE + gdbserver from MSYS2 (image: ``tenrec-fixture-windows_debugger``)
    — runs only on a host with docker in Windows-container mode.

Each test skips upfront when its container runtime isn't available, so
running ``pytest -m fixture`` on a typical macOS or Linux dev box
exercises the Linux variant and skips the Windows one with a clear
message; running on a Windows CI runner with Windows containers does
the inverse (or both, if Linux containers are also enabled).

## Why Docker

The container hosts a ``gdbserver`` (or its Windows equivalent) that
pre-launches the binary in a stopped state. IDA's ``gdb`` remote
backend then attaches over TCP. This sidesteps macOS's Mach-port
``taskgated`` gate and Linux's hardened ptrace restrictions in one
move, and gives a reproducible, version-pinned environment that's
identical across developer and CI machines.

Run with::

    IDADIR=/path/to/ida python tenrec/tests/fixtures/build_fixtures.py
    IDADIR=/path/to/ida uv run pytest -m fixture \
        tenrec/tests/integration/test_debugger_runtime_memory.py
"""

from __future__ import annotations

import time

import ida_dbg
import pytest

from tenrec.plugins.models import HexEA
from tenrec.plugins.plugins.debugger import DebuggerPlugin

from ._helpers import attach, find_function, find_name_address


pytestmark = pytest.mark.fixture


# How long to wait for each debug event. Trivial fixture binary; 30s is
# paranoia, not a real bound. Fail loud past this rather than hang CI.
WAIT_TIMEOUT_SECONDS = 30
SUSPEND_POLL_SECONDS = 1

# Signature value the fixtures write to g_uninit_value. Must stay in
# sync with both sources/linux_debugger/debugger.c and
# sources/windows_debugger/debugger.c.
EXPECTED_VALUE = 0xCAFEBABE


def _global_addr(db) -> HexEA:
    """Locate ``g_uninit_value`` regardless of platform symbol-prefix rules."""
    return find_name_address(db, "g_uninit_value", "_g_uninit_value")


def _wait_for_suspend(timeout: int = WAIT_TIMEOUT_SECONDS) -> None:
    """Pump events until the process suspends, or fail loud past ``timeout``."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
            return
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, SUSPEND_POLL_SECONDS)
    pytest.fail(
        f"Process never suspended within {timeout}s; "
        f"final state={ida_dbg.get_process_state()}, "
        f"is_debugger_on={ida_dbg.is_debugger_on()}"
    )


def _teardown_active_session() -> None:
    """If a debug session is still active, exit the process and drain events."""
    if ida_dbg.is_debugger_on():
        try:
            ida_dbg.exit_process()
        except Exception:
            pass
        ida_dbg.wait_for_next_event(
            ida_dbg.WFNE_SUSP | ida_dbg.WFNE_CONT, 5
        )


def _drive_runtime_memory_read(
    db,
    debugger: DebuggerPlugin,
    container: tuple[str, int],
) -> None:
    """Run the canonical attach/break/read/step/read flow against ``db``.

    Shared body used by both the Linux and Windows variants — the only
    cross-platform difference is which database and container fixtures
    feed in. Symbol lookup uses both naked and underscore-prefixed names
    so it works whether IDA loaded a Mach-O, ELF, or PE.
    """
    host, port = container

    # Static landmarks from the database. The Linux ELF doesn't use the
    # leading-underscore convention macOS Mach-O does, but PE binaries
    # built with mingw-w64 sometimes do. Accept either spelling.
    update_func = find_function(db, "update_value", "_update_value")
    global_addr = _global_addr(db)

    debugger.load_backend(name="gdb", remote=True, host=host, port=port)
    debugger.attach(pid=-1)

    # gdbserver pre-launches the target stopped at entry. Install the
    # breakpoint after attach so IDA has the runtime layout.
    _wait_for_suspend()
    debugger.set_breakpoint(HexEA(update_func.start_ea))

    debugger.continue_execution()
    _wait_for_suspend()

    ip = debugger.get_instruction_pointer()
    assert int(ip, 16) == update_func.start_ea, (
        f"expected to stop at update_value entry "
        f"({hex(update_func.start_ea)}); IP is {ip}"
    )

    # The contract under test: at this point, g_uninit_value's runtime
    # memory must be the OS-provided BSS fill (all zeros).
    before = debugger.read_memory(global_addr, 4)
    assert before == b"\x00\x00\x00\x00", (
        f"expected zero-filled BSS at process start, got {before.hex()}"
    )

    # Run update_value to completion and verify the assignment is
    # observable via runtime memory.
    debugger.step_until_return()
    _wait_for_suspend()

    after = debugger.read_memory(global_addr, 4)
    observed = int.from_bytes(after, "little")
    assert observed == EXPECTED_VALUE, (
        f"expected runtime value {EXPECTED_VALUE:#x} after update_value; "
        f"got {observed:#x} (raw bytes: {after.hex()})"
    )

    # Walk the process to completion so cleanup doesn't have to
    # force-kill it.
    debugger.continue_execution()
    ida_dbg.wait_for_next_event(
        ida_dbg.WFNE_SUSP | ida_dbg.WFNE_CONT, 5
    )


# ---------------------------------------------------------------------------
# Linux ELF — runs on any host with a Linux docker daemon
# ---------------------------------------------------------------------------


class TestRuntimeMemoryReadsLiveDataLinux:
    @pytest.fixture
    def fresh_debugger(self, linux_debugger_db):
        debugger = attach(DebuggerPlugin, linux_debugger_db)
        try:
            yield debugger
        finally:
            _teardown_active_session()

    def test_uninitialised_global_reads_zero_then_writes_through(
        self, linux_debugger_db, fresh_debugger, gdbserver_container
    ):
        _drive_runtime_memory_read(linux_debugger_db, fresh_debugger, gdbserver_container)


# ---------------------------------------------------------------------------
# Windows PE — runs only on a host with docker in Windows-container mode
# ---------------------------------------------------------------------------


class TestRuntimeMemoryReadsLiveDataWindows:
    @pytest.fixture
    def fresh_debugger(self, windows_debugger_db):
        debugger = attach(DebuggerPlugin, windows_debugger_db)
        try:
            yield debugger
        finally:
            _teardown_active_session()

    def test_uninitialised_global_reads_zero_then_writes_through(
        self, windows_debugger_db, fresh_debugger, gdbserver_windows_container
    ):
        _drive_runtime_memory_read(
            windows_debugger_db, fresh_debugger, gdbserver_windows_container
        )
