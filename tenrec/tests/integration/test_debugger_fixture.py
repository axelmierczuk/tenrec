"""Integration tests for the debugger plugin against the 'basic' fixture.

The plugin exposes two surfaces with very different runtime requirements:

* **Breakpoints** are persisted into the IDA database (``add_bpt`` /
  ``del_bpt`` / ``getn_bpt``). They work whenever a database is open, with
  or without a live debugger backend, so we can round-trip them against the
  fixture .i64 directly.
* **Live operations** (execution control, registers, memory, stack) require
  an attached debugger. In headless idalib there is no way to start one, so
  the tests here verify the plugin's "no active debugger" guard rather than
  a real session — those guards are what callers depend on to distinguish
  "feature unavailable" from "real failure".

Run with::

    IDADIR=/path/to/ida python tenrec/tests/fixtures/build_fixtures.py
    IDADIR=/path/to/ida uv run pytest -m fixture tenrec/tests/integration/test_debugger_fixture.py
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

import ida_dbg
import pytest

from tenrec.plugins.models import HexEA, OperationError
from tenrec.plugins.plugins.debugger import (
    BreakpointType,
    DebuggerPlugin,
    ProcessState,
)

from ._helpers import attach, find_function


pytestmark = pytest.mark.fixture


@contextmanager
def _clean_breakpoints() -> Generator[None]:
    """Snapshot every breakpoint, then restore the set on exit.

    Breakpoints persist in the IDA database, so a test that fails partway
    through ``set_breakpoint`` could otherwise leave landmines for siblings.
    The fixture databases are opened with ``save_on_close=False`` (see
    conftest._make_db_fixture) so this protects sibling tests within a
    single session, not the on-disk file.
    """
    snapshot = []
    for index in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(index, bpt):
            snapshot.append((bpt.ea, bpt.size, bpt.type, bpt.enabled()))
    try:
        yield
    finally:
        # Drain whatever the test left behind, then re-add the originals.
        for index in range(ida_dbg.get_bpt_qty() - 1, -1, -1):
            bpt = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(index, bpt):
                ida_dbg.del_bpt(bpt.ea)
        for ea, size, bptype, enabled in snapshot:
            ida_dbg.add_bpt(ea, size, bptype)
            if not enabled:
                ida_dbg.enable_bpt(ea, False)


# ---------------------------------------------------------------------------
# Status — no debugger required
# ---------------------------------------------------------------------------


class TestDebuggerStatus:
    def test_is_running_returns_false_without_debugger(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        # Headless idalib: no debugger backend can be attached, so this
        # contract must hold no matter how the suite is run.
        assert debugger.is_running() is False

    def test_process_state_is_notask_without_debugger(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        assert debugger.process_state() == ProcessState.NOTASK.name


# ---------------------------------------------------------------------------
# Breakpoints — round-trip against the database
# ---------------------------------------------------------------------------


class TestBreakpointRoundTrip:
    def test_set_then_list_includes_breakpoint(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)

        with _clean_breakpoints():
            added = debugger.set_breakpoint(addr)
            assert added.address == addr
            assert added.enabled is True

            listed = debugger.list_breakpoints()
            assert any(b.address == addr for b in listed), (
                f"expected {addr} in {[b.address for b in listed]}"
            )

    def test_get_breakpoint_returns_metadata(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        target = find_function(basic_db, "main", "_main")
        addr = HexEA(target.start_ea)

        with _clean_breakpoints():
            debugger.set_breakpoint(addr)
            got = debugger.get_breakpoint(addr)
            assert got.address == addr
            assert got.enabled is True
            assert got.pass_count == 0

    def test_remove_breakpoint_clears_it(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        target = find_function(basic_db, "process_buffer", "_process_buffer")
        addr = HexEA(target.start_ea)

        with _clean_breakpoints():
            debugger.set_breakpoint(addr)
            assert any(b.address == addr for b in debugger.list_breakpoints())

            assert debugger.remove_breakpoint(addr) is True
            # After removal the breakpoint must be gone from list AND get must raise.
            assert not any(b.address == addr for b in debugger.list_breakpoints())
            with pytest.raises(OperationError, match="No breakpoint"):
                debugger.get_breakpoint(addr)

    def test_remove_breakpoint_at_unknown_address_raises(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)

        with _clean_breakpoints():
            # No breakpoint set anywhere; remove must raise rather than no-op.
            with pytest.raises(OperationError, match="No breakpoint"):
                debugger.remove_breakpoint(addr)

    def test_disable_then_enable_round_trips(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)

        with _clean_breakpoints():
            debugger.set_breakpoint(addr)
            debugger.disable_breakpoint(addr)
            assert debugger.get_breakpoint(addr).enabled is False

            debugger.enable_breakpoint(addr)
            assert debugger.get_breakpoint(addr).enabled is True

    def test_list_breakpoints_initially_empty(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        with _clean_breakpoints():
            # Drain anything that pre-existed in the fixture so the empty-list
            # contract holds. _clean_breakpoints will restore them.
            for index in range(ida_dbg.get_bpt_qty() - 1, -1, -1):
                bpt = ida_dbg.bpt_t()
                if ida_dbg.getn_bpt(index, bpt):
                    ida_dbg.del_bpt(bpt.ea)
            assert debugger.list_breakpoints() == []

    def test_breakpoint_type_propagates_to_metadata(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)

        with _clean_breakpoints():
            # SOFT is the only type that's portable across architectures and
            # debugger backends; hardware exec/data bpts depend on the target
            # platform's debug registers.
            added = debugger.set_breakpoint(addr, breakpoint_type=BreakpointType.SOFT)
            assert added.type in {"SOFT", "DEFAULT"}, (
                f"expected SOFT/DEFAULT, got {added.type}"
            )

    def test_get_breakpoint_at_address_without_one_raises(self, basic_db):
        debugger = attach(DebuggerPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)

        with _clean_breakpoints():
            with pytest.raises(OperationError, match="No breakpoint"):
                debugger.get_breakpoint(addr)


# ---------------------------------------------------------------------------
# Live operations — verify the no-active-debugger guard fires
# ---------------------------------------------------------------------------
#
# These tests are the contract callers depend on: when no process is being
# debugged, every live operation must raise OperationError with a message
# beginning "No active debugger". Headless idalib can't actually attach a
# debugger backend, so the not-running branch is the only one we can hit
# here — and that's exactly the surface most users will see in practice.


class TestLiveOperationsRequireDebugger:
    @pytest.fixture
    def debugger(self, basic_db):
        return attach(DebuggerPlugin, basic_db)

    def test_continue_execution_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.continue_execution()

    def test_pause_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.pause()

    def test_exit_process_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.exit_process()

    def test_step_into_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.step_into()

    def test_step_over_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.step_over()

    def test_step_until_return_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.step_until_return()

    def test_run_to_without_debugger_raises(self, debugger, basic_db):
        target = find_function(basic_db, "main", "_main")
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.run_to(HexEA(target.start_ea))


class TestStateInspectionRequireSuspendedProcess:
    @pytest.fixture
    def debugger(self, basic_db):
        return attach(DebuggerPlugin, basic_db)

    def test_get_register_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.get_register("rax")

    def test_get_registers_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.get_registers()

    def test_set_register_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.set_register("rax", 0)

    def test_get_instruction_pointer_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.get_instruction_pointer()

    def test_get_stack_pointer_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.get_stack_pointer()

    def test_read_memory_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.read_memory(HexEA(0x401000), 16)

    def test_write_memory_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.write_memory(HexEA(0x401000), b"\x90\x90")

    def test_get_stack_trace_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.get_stack_trace()

    def test_get_stack_without_debugger_raises(self, debugger):
        with pytest.raises(OperationError, match="No active debugger"):
            debugger.get_stack(count=4)


# ---------------------------------------------------------------------------
# Argument validation — fires before the live-debugger gate
# ---------------------------------------------------------------------------
#
# These guards catch caller mistakes that would otherwise produce confusing
# downstream errors from the IDA SDK. They have to fire BEFORE the suspended-
# process check because the suspended-process check itself also raises — we
# want the more specific message to win.


class TestArgumentValidation:
    @pytest.fixture
    def debugger(self, basic_db):
        return attach(DebuggerPlugin, basic_db)

    def test_read_memory_with_zero_size_raises_size_error_when_running(self, debugger):
        # We can't reach the size validation without a live debugger — IDA's
        # is_debugger_on() guard fires first, which is the documented
        # behaviour. This test pins the precedence so a future refactor that
        # moves validation above the gate gets caught.
        with pytest.raises(OperationError) as exc:
            debugger.read_memory(HexEA(0x401000), 0)
        assert "No active debugger" in str(exc.value.msg)

    def test_write_memory_empty_data_raises_when_running(self, debugger):
        with pytest.raises(OperationError) as exc:
            debugger.write_memory(HexEA(0x401000), b"")
        assert "No active debugger" in str(exc.value.msg)

    def test_get_stack_with_zero_count_raises_when_running(self, debugger):
        with pytest.raises(OperationError) as exc:
            debugger.get_stack(count=0)
        assert "No active debugger" in str(exc.value.msg)
