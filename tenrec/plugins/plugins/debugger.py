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

import os
import platform
from enum import IntEnum
from pathlib import Path

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


class BackendInfo(BaseModel):
    """Discovered debugger backend, suitable as a name argument to load_backend.

    A single backend can ship two plugin files: the ``*_user`` flavour for
    in-process debugging and the ``*_stub`` flavour for talking to an IDA
    remote debug server. ``local`` and ``remote`` indicate which variants
    are actually present on disk; pass ``remote=True`` to load_backend()
    for the latter.
    """

    name: str
    local: bool
    remote: bool
    files: list[str]


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


# Filename suffixes that mark a debugger backend in IDA's plugins/ directory.
# IDA names them ``<basename>_user.<ext>`` for the in-process debugger and
# ``<basename>_stub.<ext>`` for the remote-debug stub; the basename is what
# ``ida_dbg.load_debugger`` accepts as ``dbgname``.
_DEBUGGER_PLUGIN_SUFFIXES: dict[str, str] = {
    "_user": "local",
    "_stub": "remote",
}
_DEBUGGER_PLUGIN_EXTENSIONS: frozenset[str] = frozenset({".dylib", ".so", ".dll"})


def _ida_plugins_dir() -> Path | None:
    """Locate IDA's plugins/ directory using IDADIR.

    IDADIR points at the ``MacOS`` (or ``Contents/MacOS``) directory of the
    IDA install on macOS, the install root on Linux, and the install root
    on Windows. The ``plugins`` subdirectory is co-located either way.
    Returns None if IDADIR is unset or the subdirectory doesn't exist —
    callers raise the user-facing error so the message can be specific.
    """
    idadir = os.environ.get("IDADIR")
    if not idadir:
        return None
    plugins = Path(idadir) / "plugins"
    return plugins if plugins.is_dir() else None


def _scan_debugger_plugins(plugins_dir: Path) -> list[BackendInfo]:
    """Group ``*_user``/``*_stub`` files by basename into BackendInfo records."""
    backends: dict[str, BackendInfo] = {}
    for path in sorted(plugins_dir.iterdir()):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _DEBUGGER_PLUGIN_EXTENSIONS:
            continue
        for suffix, kind in _DEBUGGER_PLUGIN_SUFFIXES.items():
            if path.stem.endswith(suffix):
                name = path.stem[: -len(suffix)]
                info = backends.setdefault(
                    name, BackendInfo(name=name, local=False, remote=False, files=[])
                )
                if kind == "local":
                    info.local = True
                else:
                    info.remote = True
                info.files.append(path.name)
                break
    return sorted(backends.values(), key=lambda b: b.name)


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
            (
                "Pick the backend by matching the database's binary format: PE → 'win32', "
                "ELF → 'linux_user', Mach-O arm64 → 'arm_mac', Mach-O x86_64 → 'mac_user'. "
                "For a gdbserver/debugserver bridge, use 'gdb' with remote=True + host/port instead."
            ),
            (
                "When load_backend() reports a name isn't loadable, call list_local_backends() to "
                "see what IDA actually ships in plugins/ — the canonical names drift across "
                "versions (e.g. on Windows 11 the local x86 debugger is usually 'windbg', not 'win32')."
            ),
            "Omit name from load_backend() only when the database's target matches the host running IDA",
            "Always check is_running() before issuing live operations (registers, memory, stepping)",
            "Breakpoint set/list/remove operations work even when no debugger is attached",
            "Live operations raise OperationError with a 'no active debugger' message when off",
            "Pause the process before reading registers or memory — values are only coherent when suspended",
        ],
        examples=[
            "Local debug on the same host: `debugger_load_backend()`",
            "Discover available backend names: `debugger_list_local_backends()`",
            (
                "Linux ELF over gdbserver: "
                "`debugger_load_backend(name='gdb', remote=True, host='localhost', port=31337)`"
            ),
            (
                "Windows PE under win32_remote.exe: "
                "`debugger_load_backend(name='win32', remote=True, host='10.0.0.5', port=23946)`"
            ),
            "Set a breakpoint at main: `debugger_set_breakpoint(0x401000)`",
            "List active breakpoints: `debugger_list_breakpoints()`",
            "Step over: `debugger_step_over()`",
            "Read RAX: `debugger_get_register('rax')`",
            "Read 16 bytes at RSP: `debugger_read_memory(0x7ffeefbff000, 16)`",
        ],
        anti_examples=[
            "DON'T call read_memory or get_registers without first verifying the process is suspended",
            "DON'T call start_process under idalib without calling load_backend() first — it will return -1",
            "DON'T pick a backend that doesn't match the database's binary format (e.g. 'win32' on an ELF target)",
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
        ``attach`` return -1 until you call this.

        ## How to pick ``name``

        Match the database's binary format (visible via ``database.metadata``) to the IDA
        debugger plugin that knows how to drive that target:

        =========== ================================== ===========================================
        Target      Backend name                       Notes
        =========== ================================== ===========================================
        PE / Win    ``win32``                          x86/x86_64 Windows local + remote
        ELF / Linux ``linux_user``                     local on Linux only; use ``gdb`` elsewhere
        Mach-O ARM  ``arm_mac``                        Apple Silicon
        Mach-O x86  ``mac_user``                       Intel macs (older IDA builds)
        Any         ``gdb``                            anything reachable via gdbserver/debugserver
        =========== ================================== ===========================================

        Omit ``name`` only when the database's target matches the host running IDA — the
        plugin then auto-selects the local backend for the host platform.

        ## Local vs remote

        Set ``remote=False`` (default) for the local-debugger plugin variant. Set ``remote=True``
        plus ``host``/``port`` when you're connecting to a debug server elsewhere:

        * IDA's own remote stubs: ``mac_server_arm``, ``win32_remote.exe``, ``linux_server`` —
          pair the matching ``name`` (``arm_mac``/``win32``/``linux_user``) with ``remote=True``.
        * gdbserver / lldb's debugserver / any gdb-remote stub — use ``name="gdb"``,
          ``remote=True``. Same protocol works against Linux ELFs, Windows PEs (via MSYS2's
          gdbserver), and BSD targets.

        ## Examples

        Local debug on the same host as IDA::

            debugger.load_backend()  # auto-select

        Attach to a Linux ELF running under gdbserver in Docker::

            debugger.load_backend(name="gdb", remote=True, host="localhost", port=31337)

        Drive a Windows VM via IDA's win32_remote.exe::

            debugger.load_backend(name="win32", remote=True, host="10.0.0.5", port=23946)

        :param name: Backend plugin basename. Omit to auto-select for the host platform; pass
            an explicit value when the database's target doesn't match the host (e.g. analysing
            a Linux ELF from macOS) or when you want gdb-remote regardless of target.
        :param remote: True selects the backend's remote-stub variant; False (default) selects
            the local debugger that runs in the same process as IDA.
        :param host: Remote-debugger hostname. Only used when set; routes subsequent attach /
            start_process calls through ``set_remote_debugger``.
        :param port: Remote-debugger TCP port. Only used when ``host`` is set.
        :param password: Optional remote-debugger password. Only used when ``host`` is set.
        :return: The name of the backend that was loaded.
        :raises OperationException: If IDA refuses to load the requested backend.
        """
        chosen = name or _default_local_backend_name()
        if not ida_dbg.load_debugger(chosen, remote):
            msg = (
                f"Failed to load debugger backend {chosen!r} (remote={remote}). "
                "Call list_local_backends() to see what's actually shipped in IDA's "
                "plugins/ directory — debugger plugin filenames vary across IDA versions "
                "(notably 'win32' on Windows 11)."
            )
            raise OperationError(msg)
        if host is not None:
            ida_dbg.set_remote_debugger(host, password, port)
        return chosen

    @operation()
    def list_local_backends(self) -> list[BackendInfo]:
        """List debugger backends discoverable in IDA's plugins/ directory.

        Use this when ``load_backend`` returns "Failed to load debugger backend" for a
        name you expected to work — IDA has renamed and re-arranged debugger plugins
        across versions, so the documented name may not match what's on disk. The
        returned ``name`` field is exactly what to pass to ``load_backend``; ``local``
        and ``remote`` indicate whether ``remote=False`` and ``remote=True`` are
        valid for that name.

        Examples of what callers typically see:

        * macOS arm64: arm_mac (local + remote), gdb (local), bochs (local), pin (local)
        * Linux x64: linux (remote), gdb (local), bochs (local)
        * Windows 11: win32 (remote), windbg (local), gdb (local) — the "win32" local
          plugin may not be present, in which case the local debugger is named
          differently (frequently ``windbg``).

        :return: BackendInfo per backend basename, alphabetically sorted.
        :raises OperationException: If IDA's plugins/ directory can't be located.
        """
        plugins_dir = _ida_plugins_dir()
        if plugins_dir is None:
            msg = (
                "Could not locate IDA's plugins/ directory. Set IDADIR to the IDA "
                "install path (e.g. '/Applications/IDA Professional 9.2.app/Contents/MacOS'."
            )
            raise OperationError(msg)
        return _scan_debugger_plugins(plugins_dir)

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
