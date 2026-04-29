"""Unit tests for DebuggerPlugin.

These exercise the plugin's branching against a patched ida_dbg module —
they pin the contract that callers depend on (correct address translation,
no-active-debugger gating, suspended-process gating, error-message shape)
without needing a real IDA session.

The integration tests in ``tests/integration/test_debugger_fixture.py``
cover the same operations against a real database; the unit tests catch
regressions in branching logic faster and run without ``IDADIR``.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from tenrec.plugins.models.exceptions import OperationError
from tenrec.plugins.models.ida import HexEA
from tenrec.plugins.plugins.debugger import (
    BackendInfo,
    BreakpointData,
    BreakpointType,
    DebuggerPlugin,
    ProcessState,
    RegisterData,
    _scan_debugger_plugins,
)


@pytest.fixture
def plugin(mock_ida_database):
    p = DebuggerPlugin()
    p.database = mock_ida_database
    return p


@pytest.fixture
def fake_bpt():
    """Build a stand-in for ida_dbg.bpt_t with the attributes we read."""
    bpt = Mock()
    bpt.ea = 0x401000
    bpt.type = int(BreakpointType.SOFT)
    bpt.pass_count = 0
    bpt.condition = ""
    bpt.get_size.return_value = 0
    bpt.enabled.return_value = True
    return bpt


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class TestStatus:
    @pytest.mark.unit
    def test_is_running_proxies_is_debugger_on(self, plugin):
        with patch("tenrec.plugins.plugins.debugger.ida_dbg.is_debugger_on", return_value=True):
            assert plugin.is_running() is True

        with patch("tenrec.plugins.plugins.debugger.ida_dbg.is_debugger_on", return_value=False):
            assert plugin.is_running() is False

    @pytest.mark.unit
    def test_process_state_maps_dstate_constants(self, plugin):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_process_state",
            return_value=ProcessState.SUSPENDED.value,
        ):
            assert plugin.process_state() == "SUSPENDED"

        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_process_state",
            return_value=ProcessState.NOTASK.value,
        ):
            assert plugin.process_state() == "NOTASK"

    @pytest.mark.unit
    def test_process_state_handles_unknown_constant(self, plugin):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_process_state", return_value=42
        ):
            assert plugin.process_state() == "UNKNOWN(42)"


# ---------------------------------------------------------------------------
# Breakpoint operations
# ---------------------------------------------------------------------------


class TestBreakpoints:
    @pytest.mark.unit
    def test_set_breakpoint_translates_address(self, plugin, fake_bpt):
        with (
            patch("tenrec.plugins.plugins.debugger.ida_dbg.add_bpt", return_value=True) as add_bpt,
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.bpt_t", return_value=fake_bpt
            ),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.get_bpt", return_value=True
            ),
        ):
            result = plugin.set_breakpoint(HexEA(0x401000))

        # The plugin must hand a real ea_t int to ida_dbg, not a HexEA wrapper.
        add_bpt.assert_called_once_with(0x401000, 0, int(BreakpointType.DEFAULT))
        assert isinstance(result, BreakpointData)
        assert result.address == HexEA(0x401000)

    @pytest.mark.unit
    def test_set_breakpoint_failure_raises(self, plugin):
        with patch("tenrec.plugins.plugins.debugger.ida_dbg.add_bpt", return_value=False):
            with pytest.raises(OperationError, match="Failed to add breakpoint"):
                plugin.set_breakpoint(HexEA(0x401000))

    @pytest.mark.unit
    def test_set_breakpoint_passes_size_and_type(self, plugin, fake_bpt):
        fake_bpt.type = int(BreakpointType.WRITE)
        with (
            patch("tenrec.plugins.plugins.debugger.ida_dbg.add_bpt", return_value=True) as add_bpt,
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.bpt_t", return_value=fake_bpt
            ),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.get_bpt", return_value=True
            ),
        ):
            plugin.set_breakpoint(HexEA(0x401000), size=4, breakpoint_type=BreakpointType.WRITE)

        add_bpt.assert_called_once_with(0x401000, 4, int(BreakpointType.WRITE))

    @pytest.mark.unit
    def test_remove_breakpoint_calls_del_bpt(self, plugin):
        with (
            patch("tenrec.plugins.plugins.debugger.ida_dbg.exist_bpt", return_value=True),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.del_bpt", return_value=True
            ) as del_bpt,
        ):
            assert plugin.remove_breakpoint(HexEA(0x401000)) is True

        del_bpt.assert_called_once_with(0x401000)

    @pytest.mark.unit
    def test_remove_breakpoint_missing_raises(self, plugin):
        with patch("tenrec.plugins.plugins.debugger.ida_dbg.exist_bpt", return_value=False):
            with pytest.raises(OperationError, match="No breakpoint"):
                plugin.remove_breakpoint(HexEA(0x401000))

    @pytest.mark.unit
    def test_get_breakpoint_returns_data(self, plugin, fake_bpt):
        with (
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.bpt_t", return_value=fake_bpt
            ),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.get_bpt", return_value=True
            ),
        ):
            result = plugin.get_breakpoint(HexEA(0x401000))

        assert result.address == HexEA(0x401000)
        assert result.enabled is True
        assert result.type == "SOFT"

    @pytest.mark.unit
    def test_get_breakpoint_missing_raises(self, plugin):
        with (
            patch("tenrec.plugins.plugins.debugger.ida_dbg.bpt_t"),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.get_bpt", return_value=False
            ),
        ):
            with pytest.raises(OperationError, match="No breakpoint"):
                plugin.get_breakpoint(HexEA(0x401000))

    @pytest.mark.unit
    def test_list_breakpoints_iterates_qty(self, plugin, fake_bpt):
        # Each getn_bpt call must populate its bpt argument; emulate that via
        # the side-effect on the constructor (we return the same fake each
        # time, which is fine because we read attributes synchronously).
        with (
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.get_bpt_qty", return_value=3
            ),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.bpt_t", return_value=fake_bpt
            ),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.getn_bpt", return_value=True
            ) as getn_bpt,
        ):
            result = plugin.list_breakpoints()

        assert len(result) == 3
        # getn_bpt must be called once per index, so the iteration covers the
        # full breakpoint table — not just the first entry.
        assert getn_bpt.call_count == 3

    @pytest.mark.unit
    def test_list_breakpoints_skips_unreadable_entries(self, plugin):
        # If getn_bpt fails for a slot, that breakpoint shouldn't appear in
        # the result list — but the iteration must still continue.
        with (
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.get_bpt_qty", return_value=2
            ),
            patch("tenrec.plugins.plugins.debugger.ida_dbg.bpt_t"),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.getn_bpt", return_value=False
            ),
        ):
            assert plugin.list_breakpoints() == []

    @pytest.mark.unit
    def test_enable_breakpoint_routes_through_enable_bpt(self, plugin):
        with (
            patch("tenrec.plugins.plugins.debugger.ida_dbg.exist_bpt", return_value=True),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.enable_bpt", return_value=True
            ) as enable_bpt,
        ):
            assert plugin.enable_breakpoint(HexEA(0x401000)) is True

        enable_bpt.assert_called_once_with(0x401000, True)

    @pytest.mark.unit
    def test_disable_breakpoint_routes_through_enable_bpt_with_false(self, plugin):
        with (
            patch("tenrec.plugins.plugins.debugger.ida_dbg.exist_bpt", return_value=True),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.enable_bpt", return_value=True
            ) as enable_bpt,
        ):
            plugin.disable_breakpoint(HexEA(0x401000))

        enable_bpt.assert_called_once_with(0x401000, False)


# ---------------------------------------------------------------------------
# Live-operation gates
# ---------------------------------------------------------------------------


class TestLiveOperationGates:
    @pytest.mark.unit
    @pytest.mark.parametrize(
        "method,kwargs",
        [
            ("continue_execution", {}),
            ("pause", {}),
            ("exit_process", {}),
            ("step_into", {}),
            ("step_over", {}),
            ("step_until_return", {}),
            ("run_to", {"address": HexEA(0x401000)}),
        ],
    )
    def test_execution_ops_require_debugger(self, plugin, method, kwargs):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.is_debugger_on", return_value=False
        ):
            with pytest.raises(OperationError, match="No active debugger"):
                getattr(plugin, method)(**kwargs)

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "method,kwargs",
        [
            ("get_register", {"name": "rax"}),
            ("get_registers", {}),
            ("set_register", {"name": "rax", "value": 0}),
            ("get_instruction_pointer", {}),
            ("get_stack_pointer", {}),
            ("read_memory", {"address": HexEA(0x401000), "size": 4}),
            ("write_memory", {"address": HexEA(0x401000), "data": b"\x90"}),
            ("get_stack_trace", {}),
            ("get_stack", {"count": 4}),
        ],
    )
    def test_state_ops_require_debugger(self, plugin, method, kwargs):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.is_debugger_on", return_value=False
        ):
            with pytest.raises(OperationError, match="No active debugger"):
                getattr(plugin, method)(**kwargs)

    @pytest.mark.unit
    def test_state_ops_require_suspended_process(self, plugin):
        # Debugger is on, but the process is running — the second guard fires.
        with (
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.is_debugger_on", return_value=True
            ),
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.get_process_state",
                return_value=ProcessState.RUNNING.value,
            ),
        ):
            with pytest.raises(OperationError, match="not suspended"):
                plugin.get_register("rax")

            with pytest.raises(OperationError, match="not suspended"):
                plugin.get_instruction_pointer()


# ---------------------------------------------------------------------------
# Live-operation behaviour when guards pass
# ---------------------------------------------------------------------------


@pytest.fixture
def live_debugger():
    """Patches that present the plugin with a happy-path debugger state."""
    with (
        patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.is_debugger_on", return_value=True
        ),
        patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_process_state",
            return_value=ProcessState.SUSPENDED.value,
        ),
    ):
        yield


class TestLiveOperationsHappyPath:
    @pytest.mark.unit
    def test_get_instruction_pointer_returns_hexea(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_ip_val", return_value=0x401234
        ):
            ip = plugin.get_instruction_pointer()
        assert ip == HexEA(0x401234)

    @pytest.mark.unit
    def test_get_stack_pointer_returns_hexea(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_sp_val",
            return_value=0x7FFE_EFBF_F000,
        ):
            sp = plugin.get_stack_pointer()
        assert sp == HexEA(0x7FFE_EFBF_F000)

    @pytest.mark.unit
    def test_get_register_wraps_int_value(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_reg_val", return_value=0xDEADBEEF
        ):
            reg = plugin.get_register("rax")
        assert reg == RegisterData(name="rax", value="0xdeadbeef", kind="int")

    @pytest.mark.unit
    def test_get_register_handles_bytes_value(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_reg_val", return_value=b"\x01\x02"
        ):
            reg = plugin.get_register("xmm0")
        assert reg.kind == "bytes"
        assert reg.value == "0102"

    @pytest.mark.unit
    def test_get_register_unknown_register_raises(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.get_reg_val",
            side_effect=RuntimeError("unknown register"),
        ):
            with pytest.raises(OperationError, match="Failed to read register"):
                plugin.get_register("not_a_real_register")

    @pytest.mark.unit
    def test_set_register_calls_set_reg_val(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.set_reg_val", return_value=True
        ) as set_reg_val:
            assert plugin.set_register("rax", 0xCAFE) is True

        set_reg_val.assert_called_once_with("rax", 0xCAFE)

    @pytest.mark.unit
    def test_set_register_failure_raises(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.set_reg_val", return_value=False
        ):
            with pytest.raises(OperationError, match="Failed to set register"):
                plugin.set_register("rax", 0)

    @pytest.mark.unit
    def test_read_memory_returns_bytes(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_idd.dbg_read_memory",
            return_value=b"\x90\x90\x90\x90",
        ):
            data = plugin.read_memory(HexEA(0x401000), 4)
        assert data == b"\x90\x90\x90\x90"

    @pytest.mark.unit
    def test_read_memory_short_read_raises(self, plugin, live_debugger):
        # IDA returns a shorter buffer when the page isn't mapped — we must
        # surface that as an explicit error rather than silently truncating.
        with patch(
            "tenrec.plugins.plugins.debugger.ida_idd.dbg_read_memory",
            return_value=b"\x90\x90",
        ):
            with pytest.raises(OperationError, match="Short read"):
                plugin.read_memory(HexEA(0x401000), 4)

    @pytest.mark.unit
    def test_read_memory_zero_size_raises_after_gates(self, plugin, live_debugger):
        with pytest.raises(OperationError, match="size must be positive"):
            plugin.read_memory(HexEA(0x401000), 0)

    @pytest.mark.unit
    def test_write_memory_returns_byte_count(self, plugin, live_debugger):
        # dbg_write_memory returns bool; the plugin maps success → payload size.
        with patch(
            "tenrec.plugins.plugins.debugger.ida_idd.dbg_write_memory", return_value=True
        ):
            assert plugin.write_memory(HexEA(0x401000), b"\x90\x90\x90\x90") == 4

    @pytest.mark.unit
    def test_write_memory_failure_raises(self, plugin, live_debugger):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_idd.dbg_write_memory", return_value=False
        ):
            with pytest.raises(OperationError, match="Failed to write"):
                plugin.write_memory(HexEA(0x401000), b"\x90")

    @pytest.mark.unit
    def test_write_memory_empty_data_raises(self, plugin, live_debugger):
        with pytest.raises(OperationError, match="data must be non-empty"):
            plugin.write_memory(HexEA(0x401000), b"")

    @pytest.mark.unit
    def test_get_stack_reads_word_size_words(self, plugin, live_debugger):
        # The default mock_ida_database fixture builds a frozen DatabaseMetadata;
        # swap in a Mock so we can set bitness directly without rebuilding it.
        plugin.database.metadata = Mock(bitness=64)
        with (
            patch(
                "tenrec.plugins.plugins.debugger.ida_dbg.get_sp_val", return_value=0x1000
            ),
            patch(
                "tenrec.plugins.plugins.debugger.ida_idd.dbg_read_memory",
                return_value=b"\x11\x22\x33\x44\x55\x66\x77\x88"
                + b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11",
            ) as read_mem,
        ):
            stack = plugin.get_stack(count=2)

        # 64-bit metadata → read 16 bytes total, decode as two little-endian
        # 8-byte values from the start of the stack.
        read_mem.assert_called_once_with(0x1000, 16)
        assert stack == [
            HexEA(0x8877665544332211),
            HexEA(0x1100FFEEDDCCBBAA),
        ]

    @pytest.mark.unit
    def test_get_stack_zero_count_raises(self, plugin, live_debugger):
        plugin.database.metadata = Mock(bitness=64)
        with pytest.raises(OperationError, match="count must be positive"):
            plugin.get_stack(count=0)


# ---------------------------------------------------------------------------
# start_process — straddles the gates: exists in any state, but errors map
# ---------------------------------------------------------------------------


class TestStartProcess:
    @pytest.mark.unit
    def test_returns_value_when_idabacked_call_succeeds(self, plugin):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.start_process", return_value=1
        ):
            assert plugin.start_process(path="/tmp/whatever") == 1

    @pytest.mark.unit
    def test_returns_zero_for_user_cancelled(self, plugin):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.start_process", return_value=0
        ):
            # User cancellation is not an error — pass it through verbatim.
            assert plugin.start_process(path="/tmp/whatever") == 0

    @pytest.mark.unit
    def test_raises_on_minus_one(self, plugin):
        with patch(
            "tenrec.plugins.plugins.debugger.ida_dbg.start_process", return_value=-1
        ):
            with pytest.raises(OperationError, match="Failed to start process"):
                plugin.start_process(path="/tmp/whatever")


# ---------------------------------------------------------------------------
# list_local_backends — discovery against IDA's plugins/ directory
# ---------------------------------------------------------------------------


class TestScanDebuggerPlugins:
    """Direct tests for the scan helper, decoupled from filesystem layout."""

    @pytest.mark.unit
    def test_groups_user_and_stub_into_one_record(self, tmp_path):
        # The point of grouping by basename: a single backend ships up to
        # two files (local + remote stub). The scan must surface them as
        # one record with both flags set, not two separate entries.
        (tmp_path / "arm_mac_user.dylib").write_bytes(b"")
        (tmp_path / "arm_mac_stub.dylib").write_bytes(b"")

        backends = _scan_debugger_plugins(tmp_path)
        assert len(backends) == 1
        assert backends[0] == BackendInfo(
            name="arm_mac",
            local=True,
            remote=True,
            files=["arm_mac_stub.dylib", "arm_mac_user.dylib"],
        )

    @pytest.mark.unit
    def test_marks_local_only_when_only_user_present(self, tmp_path):
        (tmp_path / "gdb_user.dylib").write_bytes(b"")

        backends = _scan_debugger_plugins(tmp_path)
        assert len(backends) == 1
        assert backends[0].name == "gdb"
        assert backends[0].local is True
        assert backends[0].remote is False

    @pytest.mark.unit
    def test_marks_remote_only_when_only_stub_present(self, tmp_path):
        # The macOS arm64 case for win32: only the stub ships, so a caller
        # asking for local win32 will fail. The scan reports remote=True,
        # local=False, which is the right signal to tell the caller to
        # use remote=True or pick a different backend.
        (tmp_path / "win32_stub.dll").write_bytes(b"")

        backends = _scan_debugger_plugins(tmp_path)
        assert len(backends) == 1
        assert backends[0].name == "win32"
        assert backends[0].local is False
        assert backends[0].remote is True

    @pytest.mark.unit
    def test_handles_dll_so_and_dylib(self, tmp_path):
        # The same test should pass on any host: the scan accepts every
        # extension IDA uses across platforms, not just the host's.
        (tmp_path / "win32_user.dll").write_bytes(b"")
        (tmp_path / "linux_user.so").write_bytes(b"")
        (tmp_path / "arm_mac_user.dylib").write_bytes(b"")

        names = {b.name for b in _scan_debugger_plugins(tmp_path)}
        assert names == {"win32", "linux", "arm_mac"}

    @pytest.mark.unit
    def test_ignores_non_debugger_plugins(self, tmp_path):
        # Plenty of non-debugger plugins live in the same directory
        # (decompilers, signature engines, scripting bridges). They use
        # different naming conventions and must NOT show up as backends.
        (tmp_path / "hexx64.dylib").write_bytes(b"")          # decompiler
        (tmp_path / "idapython3.dylib").write_bytes(b"")      # python bridge
        (tmp_path / "dwarf.dylib").write_bytes(b"")           # debug info
        (tmp_path / "arm_mac_user.dylib").write_bytes(b"")    # actual debugger

        backends = _scan_debugger_plugins(tmp_path)
        names = [b.name for b in backends]
        assert names == ["arm_mac"]

    @pytest.mark.unit
    def test_ignores_non_plugin_files(self, tmp_path):
        # plugins/ on real installs has plugins.cfg, .pdb, README files,
        # and subdirectories. The scan must skip anything that isn't a
        # plugin shared library.
        (tmp_path / "plugins.cfg").write_text("# a config file")
        (tmp_path / "ida_feeds").mkdir()
        (tmp_path / "arm_mac_user.dylib").write_bytes(b"")

        backends = _scan_debugger_plugins(tmp_path)
        assert [b.name for b in backends] == ["arm_mac"]

    @pytest.mark.unit
    def test_returns_alphabetical_order(self, tmp_path):
        # Stable ordering keeps the wire output deterministic for callers
        # that diff successive runs (e.g. CI checking that a tool's
        # advertised backend list hasn't changed).
        for name in ("xnu", "arm_mac", "gdb", "linux"):
            suffix = "_user" if name != "linux" else "_stub"
            ext = ".dll" if name == "linux" else ".dylib"
            (tmp_path / f"{name}{suffix}{ext}").write_bytes(b"")

        names = [b.name for b in _scan_debugger_plugins(tmp_path)]
        assert names == sorted(names)


class TestListLocalBackendsOperation:
    """End-to-end tests against the operation, with the plugins/ dir patched."""

    @pytest.mark.unit
    def test_returns_scan_result(self, plugin, tmp_path):
        (tmp_path / "arm_mac_user.dylib").write_bytes(b"")
        (tmp_path / "gdb_user.dylib").write_bytes(b"")
        with patch(
            "tenrec.plugins.plugins.debugger._ida_plugins_dir",
            return_value=tmp_path,
        ):
            backends = plugin.list_local_backends()
        names = [b.name for b in backends]
        assert names == ["arm_mac", "gdb"]

    @pytest.mark.unit
    def test_raises_when_idadir_unavailable(self, plugin):
        with patch(
            "tenrec.plugins.plugins.debugger._ida_plugins_dir",
            return_value=None,
        ):
            with pytest.raises(OperationError, match="Could not locate IDA's plugins"):
                plugin.list_local_backends()
