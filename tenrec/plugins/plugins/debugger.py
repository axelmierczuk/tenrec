"""Debugger plugin: drives IDA's debugger via the ida_dbg Python SDK.

Two distinct surfaces live here:

* **Breakpoints** are persisted into the IDA database itself — ``add_bpt`` /
  ``del_bpt`` / ``getn_bpt`` work without an attached debugger backend, so
  these operations are usable whenever a database is open.
* **Live operations** (execution control, registers, memory, stack) require
  an attached debugger process. They raise ``OperationError`` with a
  consistent "no active debugger" message when called outside a debug
  session, so callers can distinguish "feature unavailable" from "real
  failure".
"""

from __future__ import annotations

import platform
from enum import IntEnum

import ida_dbg
import ida_funcs
import ida_idd
from pydantic import BaseModel

from tenrec.plugins.models import (
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)


class BreakpointType(IntEnum):
    """Subset of ida_idd breakpoint types exposed via this plugin."""

    SOFT = ida_idd.BPT_SOFT
    EXEC = ida_idd.BPT_EXEC
    WRITE = ida_idd.BPT_WRITE
    RDWR = ida_idd.BPT_RDWR
    DEFAULT = ida_idd.BPT_DEFAULT


class ProcessState(IntEnum):
    """Mirror of ida_dbg.DSTATE_* so the wire format is a stable string."""

    NOTASK = ida_dbg.DSTATE_NOTASK
    SUSPENDED = ida_dbg.DSTATE_SUSP
    RUNNING = ida_dbg.DSTATE_RUN


class BreakpointData(BaseModel):
    address: HexEA
    size: int
    type: str
    enabled: bool
    pass_count: int
    condition: str | None

    @classmethod
    def from_bpt(cls, bpt: ida_dbg.bpt_t) -> BreakpointData:
        try:
            type_name = BreakpointType(bpt.type).name
        except ValueError:
            type_name = f"UNKNOWN({bpt.type})"
        return cls(
            address=HexEA(bpt.ea),
            size=bpt.get_size(),
            type=type_name,
            enabled=bpt.enabled(),
            pass_count=bpt.pass_count,
            condition=bpt.condition or None,
        )


class RegisterData(BaseModel):
    name: str
    value: str
    kind: str

    @classmethod
    def from_value(cls, name: str, value: float | bytes) -> RegisterData:
        if isinstance(value, int):
            return cls(name=name, value=f"0x{value:x}", kind="int")
        if isinstance(value, float):
            return cls(name=name, value=repr(value), kind="float")
        if isinstance(value, bytes | bytearray):
            return cls(name=name, value=bytes(value).hex(), kind="bytes")
        return cls(name=name, value=str(value), kind="other")


class StackFrameData(BaseModel):
    index: int
    address: HexEA
    function_name: str | None


def _require_debugger() -> None:
    """Raise OperationError unless a debugger is attached and queryable."""
    if not ida_dbg.is_debugger_on():
        msg = "No active debugger session — start_process or attach_process first"
        raise OperationError(msg)


def _require_suspended() -> None:
    """Raise unless the debugged process is currently suspended.

    Register and memory access in IDA's debugger interface only return
    coherent values while the process is paused; calling them on a running
    target either blocks or returns stale cache.
    """
    _require_debugger()
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        msg = "Debugger is attached but the process is not suspended"
        raise OperationError(msg)


def _set_breakpoint_enabled(address: HexEA, *, enabled: bool) -> bool:
    """Toggle breakpoint enabled state, raising if no breakpoint exists."""
    if not ida_dbg.exist_bpt(address.ea_t):
        msg = f"No breakpoint at {address}"
        raise OperationError(msg)
    return ida_dbg.enable_bpt(address.ea_t, enabled)


def _default_local_backend_name() -> str:
    """Return the IDA debugger plugin name for the host platform/arch.

    These are the basenames (no ``.dylib``/``.so``/``.dll``) that IDA's
    plugins/ directory ships under each OS. ``load_debugger`` accepts the
    basename and resolves the file extension itself. The selection has to
    match the *host* OS, not the analysed binary's target — IDA's local
    debugger debugs processes on the same machine that runs IDA.
    """
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Darwin":
        # On Apple Silicon the relevant plugin is arm_mac_user; Intel macs
        # used mac_user (no longer shipped on recent IDA builds).
        if machine in {"arm64", "aarch64"}:
            return "arm_mac_user"
        return "mac_user"
    if system == "Linux":
        return "linux_user"
    if system == "Windows":
        return "win32"
    msg = f"No default debugger backend known for platform {system!r} ({machine})"
    raise OperationError(msg)


class DebuggerPlugin(PluginBase):
    """Drive IDA's debugger: breakpoints, execution control, register/memory/stack inspection."""

    name = "debugger"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Manage breakpoints, control debugger execution, and inspect process state through IDA's "
            "Python debugger SDK. Use for dynamic analysis: setting breakpoints to halt at points of "
            "interest, stepping through code, reading registers and memory, and walking the call stack."
        ),
        interaction_style=[
            "In headless idalib, call load_backend() once before start_process() — no debugger is loaded by default",
            "Always check is_running() before issuing live operations (registers, memory, stepping)",
            "Breakpoint set/list/remove operations work even when no debugger is attached",
            "Live operations raise OperationError with a 'no active debugger' message when off",
            "Pause the process before reading registers or memory — values are only coherent when suspended",
        ],
        examples=[
            "Load default local backend: `debugger_load_backend()`",
            "Set a breakpoint at main: `debugger_set_breakpoint(0x401000)`",
            "List active breakpoints: `debugger_list_breakpoints()`",
            "Step over: `debugger_step_over()`",
            "Read RAX: `debugger_get_register('rax')`",
            "Read 16 bytes at RSP: `debugger_read_memory(0x7ffeefbff000, 16)`",
        ],
        anti_examples=[
            "DON'T call read_memory or get_registers without first verifying the process is suspended",
            "DON'T call start_process under idalib without calling load_backend() first — it will return -1",
            "DON'T rely on memory reads while the process is running — values may be stale",
        ],
    )


    @operation(unsafe=True)
    def load_backend(
        self,
        name: str | None = None,
        remote: bool = False,
        host: str | None = None,
        port: int = 0,
        password: str = "",
    ) -> str:
        """Load an IDA debugger backend and optionally configure a remote endpoint.

        In headless ``idalib`` no debugger plugin is loaded by default, so ``start_process`` and
        ``attach`` return -1 until you call this. Pass ``name`` to pick an explicit backend
        (basename of the IDA plugin file — e.g. ``arm_mac``, ``linux_user``, ``win32``, ``gdb``);
        omit ``name`` to auto-select a sensible default for the host platform.

        For headless workflows on platforms where the local debugger needs special entitlements
        (notably macOS arm64), pair ``name="gdb"``/``remote=True`` with a pre-launched ``debugserver``
        and pass ``host``/``port`` here so subsequent ``attach`` / ``start_process`` calls route
        through the gdb-remote bridge.

        :param name: Backend plugin basename, or None to auto-select for the host.
        :param remote: True for the remote-debugger stub variant; False for the local debugger.
        :param host: Optional remote-debugger hostname; configured via set_remote_debugger.
        :param port: Optional remote-debugger TCP port (only used when host is set).
        :param password: Optional remote-debugger password (only used when host is set).
        :return: The name of the backend that was loaded.
        :raises OperationException: If IDA refuses to load the requested backend.
        """
        chosen = name or _default_local_backend_name()
        if not ida_dbg.load_debugger(chosen, remote):
            msg = (
                f"Failed to load debugger backend {chosen!r} (remote={remote}). "
                "Verify the corresponding plugin file exists in IDA's plugins/ directory."
            )
            raise OperationError(msg)
        if host is not None:
            ida_dbg.set_remote_debugger(host, password, port)
        return chosen

    @operation(unsafe=True)
    def attach(self, pid: int = -1, event_id: int = -1) -> int:
        """Attach the loaded debugger to an already-running process.

        For local debuggers, pass an OS process id. For gdb-remote backends connected through a
        pre-launched ``debugserver``/``gdbserver``, pass ``pid=-1`` — the remote stub already has
        a target and IDA only needs to take ownership of the session.

        :param pid: Process ID to attach to, or -1 to take over whatever the remote backend hosts.
        :param event_id: Optional event id for resuming after a specific event; -1 for none.
        :return: 1 on success; 0 if cancelled by the user; -1 on failure.
        :raises OperationException: If attach_process returned -1.
        """
        result = ida_dbg.attach_process(pid, event_id)
        if result == -1:
            msg = f"Failed to attach to pid={pid}"
            raise OperationError(msg)
        return result

    @operation()
    def is_running(self) -> bool:
        """Return True if a debugger is attached to a process.

        :return: True if the debugger is on (process started or attached), False otherwise.
        """
        return ida_dbg.is_debugger_on()

    @operation()
    def process_state(self) -> str:
        """Return the current process state as a stable string identifier.

        :return: One of "NOTASK" (no debug session), "RUNNING", or "SUSPENDED".
        """
        state = ida_dbg.get_process_state()
        try:
            return ProcessState(state).name
        except ValueError:
            return f"UNKNOWN({state})"


    @operation()
    def set_breakpoint(
        self,
        address: HexEA,
        size: int = 0,
        breakpoint_type: BreakpointType = BreakpointType.DEFAULT,
    ) -> BreakpointData:
        """Add a breakpoint at the specified address.

        Works against the IDA database — does not require an active debugger session. The breakpoint
        becomes active when a debugger is started or attached.

        :param address: The effective address where the breakpoint should be placed.
        :param size: Breakpoint size; 0 for software breakpoints, >0 for hardware data breakpoints.
        :param breakpoint_type: Breakpoint kind (SOFT, EXEC, WRITE, RDWR, DEFAULT).
        :return: The added breakpoint as BreakpointData.
        :raises OperationException: If the breakpoint could not be added at the given address.
        """
        if not ida_dbg.add_bpt(address.ea_t, size, int(breakpoint_type)):
            msg = f"Failed to add breakpoint at {address}"
            raise OperationError(msg)
        bpt = ida_dbg.bpt_t()
        if not ida_dbg.get_bpt(address.ea_t, bpt):
            msg = f"Breakpoint added at {address} but readback failed"
            raise OperationError(msg)
        return BreakpointData.from_bpt(bpt)

    @operation()
    def remove_breakpoint(self, address: HexEA) -> bool:
        """Remove a breakpoint at the specified address.

        :param address: Effective address of the breakpoint to remove.
        :return: True if a breakpoint was removed.
        :raises OperationException: If no breakpoint exists at the address or removal failed.
        """
        if not ida_dbg.exist_bpt(address.ea_t):
            msg = f"No breakpoint at {address}"
            raise OperationError(msg)
        if not ida_dbg.del_bpt(address.ea_t):
            msg = f"Failed to remove breakpoint at {address}"
            raise OperationError(msg)
        return True

    @operation()
    def get_breakpoint(self, address: HexEA) -> BreakpointData:
        """Get details for the breakpoint at a specific address.

        :param address: Effective address to look up.
        :return: BreakpointData with type, size, enabled state, pass count and condition.
        :raises OperationException: If no breakpoint exists at the given address.
        """
        bpt = ida_dbg.bpt_t()
        if not ida_dbg.get_bpt(address.ea_t, bpt):
            msg = f"No breakpoint at {address}"
            raise OperationError(msg)
        return BreakpointData.from_bpt(bpt)

    @operation(options=[PaginatedParameter()])
    def list_breakpoints(self) -> list[BreakpointData]:
        """List every breakpoint currently registered with the database.

        :return: All breakpoints as BreakpointData (empty list if none are set).
        """
        result = []
        for index in range(ida_dbg.get_bpt_qty()):
            bpt = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(index, bpt):
                result.append(BreakpointData.from_bpt(bpt))
        return result

    @operation()
    def enable_breakpoint(self, address: HexEA) -> bool:
        """Enable an existing breakpoint at the specified address.

        :param address: Effective address of the breakpoint to enable.
        :return: True if the breakpoint was enabled.
        :raises OperationException: If no breakpoint exists at the address.
        """
        return _set_breakpoint_enabled(address, enabled=True)

    @operation()
    def disable_breakpoint(self, address: HexEA) -> bool:
        """Disable an existing breakpoint at the specified address.

        :param address: Effective address of the breakpoint to disable.
        :return: True if the breakpoint was disabled.
        :raises OperationException: If no breakpoint exists at the address.
        """
        return _set_breakpoint_enabled(address, enabled=False)


    @operation(unsafe=True)
    def start_process(
        self, path: str | None = None, args: str | None = None, sdir: str | None = None
    ) -> int:
        """Start a new process under the debugger.

        :param path: Path to the executable; defaults to the database's input file when omitted.
        :param args: Command-line arguments string (or None for none).
        :param sdir: Starting working directory (or None for IDA's default).
        :return: 1 on success, 0 if the user cancelled, -1 if the process could not be started.
        :raises OperationException: If start_process returned -1 (impossible to create process).
        """
        result = ida_dbg.start_process(path, args, sdir)
        if result == -1:
            msg = f"Failed to start process: path={path!r}"
            raise OperationError(msg)
        return result

    @operation(unsafe=True)
    def continue_execution(self) -> bool:
        """Resume execution of a suspended debugged process.

        :return: True on success.
        :raises OperationException: If no debugger is active.
        """
        _require_debugger()
        return ida_dbg.continue_process()

    @operation(unsafe=True)
    def pause(self) -> bool:
        """Suspend the debugged process.

        :return: True on success.
        :raises OperationException: If no debugger is active.
        """
        _require_debugger()
        return ida_dbg.suspend_process()

    @operation(unsafe=True)
    def exit_process(self) -> bool:
        """Terminate the debugged process.

        :return: True on success.
        :raises OperationException: If no debugger is active.
        """
        _require_debugger()
        return ida_dbg.exit_process()

    @operation(unsafe=True)
    def step_into(self) -> bool:
        """Step into the next instruction.

        :return: True if the request was accepted by the debugger.
        :raises OperationException: If no debugger is active.
        """
        _require_debugger()
        return ida_dbg.step_into()

    @operation(unsafe=True)
    def step_over(self) -> bool:
        """Step over the next instruction (does not descend into calls).

        :return: True if the request was accepted by the debugger.
        :raises OperationException: If no debugger is active.
        """
        _require_debugger()
        return ida_dbg.step_over()

    @operation(unsafe=True)
    def step_until_return(self) -> bool:
        """Run until the current function returns.

        :return: True if the request was accepted by the debugger.
        :raises OperationException: If no debugger is active.
        """
        _require_debugger()
        return ida_dbg.step_until_ret()

    @operation(unsafe=True)
    def run_to(self, address: HexEA) -> bool:
        """Run the process until it reaches the given address.

        :param address: Effective address to run to.
        :return: True if the request was accepted by the debugger.
        :raises OperationException: If no debugger is active.
        """
        _require_debugger()
        return ida_dbg.run_to(address.ea_t)


    @operation()
    def get_instruction_pointer(self) -> HexEA:
        """Return the current instruction pointer (PC/EIP/RIP).

        :return: HexEA of the instruction pointer.
        :raises OperationException: If the process is not suspended.
        """
        _require_suspended()
        return HexEA(int(ida_dbg.get_ip_val()))

    @operation()
    def get_stack_pointer(self) -> HexEA:
        """Return the current stack pointer (SP/ESP/RSP).

        :return: HexEA of the stack pointer.
        :raises OperationException: If the process is not suspended.
        """
        _require_suspended()
        return HexEA(int(ida_dbg.get_sp_val()))

    @operation()
    def get_register(self, name: str) -> RegisterData:
        """Read the value of a single register by name.

        :param name: Register name (e.g. "rax", "eip").
        :return: RegisterData with name, hex/string value, and value kind ("int", "float", "bytes").
        :raises OperationException: If the process is not suspended or the register is unknown.
        """
        _require_suspended()
        try:
            value = ida_dbg.get_reg_val(name)
        except Exception as exc:
            msg = f"Failed to read register {name!r}: {exc}"
            raise OperationError(msg) from exc
        return RegisterData.from_value(name, value)

    @operation(unsafe=True)
    def set_register(self, name: str, value: int) -> bool:
        """Set a register value (integer registers only).

        :param name: Register name.
        :param value: New integer value to assign.
        :return: True on success.
        :raises OperationException: If the process is not suspended or the assignment fails.
        """
        _require_suspended()
        if not ida_dbg.set_reg_val(name, value):
            msg = f"Failed to set register {name!r} to {value:#x}"
            raise OperationError(msg)
        return True

    @operation(options=[PaginatedParameter()])
    def get_registers(self) -> list[RegisterData]:
        """Read all registers for the currently selected thread.

        :return: List of RegisterData (one per register), or empty list when none readable.
        :raises OperationException: If the process is not suspended.
        """
        _require_suspended()
        tid = ida_dbg.get_current_thread()
        regvals = ida_dbg.get_reg_vals(tid)
        if not regvals:
            return []

        # ``get_reg_vals`` returns parallel arrays of values and register info on
        # different IDA builds; the most reliable path is to walk register names
        # via the debugger's introspection and call get_reg_val per name.
        result: list[RegisterData] = []
        for name in _enumerate_register_names():
            try:
                value = ida_dbg.get_reg_val(name)
            except Exception:
                continue
            result.append(RegisterData.from_value(name, value))
        return result


    @operation()
    def read_memory(self, address: HexEA, size: int) -> bytes:
        """Read ``size`` bytes from the debugged process at ``address``.

        :param address: Source address in the debugged process.
        :param size: Number of bytes to read (must be > 0).
        :return: The bytes read from process memory.
        :raises OperationException: If the process is not suspended, or the read failed/short.
        """
        _require_suspended()
        if size <= 0:
            msg = f"size must be positive, got {size}"
            raise OperationError(msg)
        # ida_idd.dbg_read_memory is the buffer-returning Python wrapper;
        # ida_dbg.read_dbg_memory is the SWIG-level (ea, buf, size) call.
        buffer = ida_idd.dbg_read_memory(address.ea_t, size)
        if buffer is None or len(buffer) != size:
            got = 0 if buffer is None else len(buffer)
            msg = f"Short read at {address}: requested {size} bytes, got {got}"
            raise OperationError(msg)
        return bytes(buffer)

    @operation(unsafe=True)
    def write_memory(self, address: HexEA, data: bytes) -> int:
        """Write ``data`` to the debugged process at ``address``.

        :param address: Destination address in the debugged process.
        :param data: Bytes to write.
        :return: Number of bytes successfully written.
        :raises OperationException: If the process is not suspended, or the write failed.
        """
        _require_suspended()
        if not data:
            msg = "data must be non-empty"
            raise OperationError(msg)
        # dbg_write_memory returns bool (True on success), so map that to the
        # full payload size for the operation contract.
        ok = ida_idd.dbg_write_memory(address.ea_t, bytes(data))
        if not ok:
            msg = f"Failed to write {len(data)} bytes at {address}"
            raise OperationError(msg)
        return len(data)


    @operation(options=[PaginatedParameter()])
    def get_stack_trace(self) -> list[StackFrameData]:
        """Collect the call stack of the currently selected thread.

        :return: List of StackFrameData ordered from innermost to outermost frame.
        :raises OperationException: If the process is not suspended or the stack cannot be unwound.
        """
        _require_suspended()
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()
        if not ida_dbg.collect_stack_trace(tid, trace):
            msg = "Failed to collect stack trace"
            raise OperationError(msg)

        frames: list[StackFrameData] = []
        for index in range(trace.size()):
            frame = trace.at(index)
            ea = int(frame.callea) if hasattr(frame, "callea") else int(frame.fp)
            frames.append(
                StackFrameData(
                    index=index,
                    address=HexEA(ea),
                    function_name=_function_name_at(ea),
                )
            )
        return frames

    @operation(options=[PaginatedParameter()])
    def get_stack(self, count: int = 16) -> list[HexEA]:
        """Read ``count`` machine words from the top of the stack.

        :param count: Number of pointer-sized words to read (must be > 0).
        :return: List of HexEA values starting at SP.
        :raises OperationException: If the process is not suspended or the read fails.
        """
        _require_suspended()
        if count <= 0:
            msg = f"count must be positive, got {count}"
            raise OperationError(msg)

        bitness = self.database.metadata.bitness
        word_size = bitness // 8
        sp = int(ida_dbg.get_sp_val())
        total = word_size * count
        raw = ida_idd.dbg_read_memory(sp, total)
        if raw is None or len(raw) != total:
            got = 0 if raw is None else len(raw)
            msg = f"Short stack read at {hex(sp)}: requested {total} bytes, got {got}"
            raise OperationError(msg)
        return [
            HexEA(int.from_bytes(raw[i : i + word_size], "little"))
            for i in range(0, total, word_size)
        ]


def _enumerate_register_names() -> list[str]:
    """Return the list of register names known to the active debugger.

    Falls back to the empty list if the debugger isn't loaded (the calling
    operation will already have guarded against that case).
    """
    dbg = getattr(ida_dbg, "get_dbg", None)
    if dbg is None:
        return []
    try:
        debugger = dbg()
    except Exception:
        return []
    if debugger is None:
        return []
    names: list[str] = []
    try:
        for index in range(debugger.nregs):
            reg = debugger.regs(index)
            if reg.name:
                names.append(reg.name)
    except Exception:
        return []
    return names


def _function_name_at(ea: int) -> str | None:
    """Return the IDA function name at ``ea`` if one exists, else None."""
    try:
        func = ida_funcs.get_func(ea)
        if not func:
            return None
        return ida_funcs.get_func_name(func.start_ea) or None
    except Exception:
        return None


plugin = DebuggerPlugin()
