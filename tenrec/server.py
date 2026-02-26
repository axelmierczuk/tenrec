import threading
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.server import Transport
from ida_domain.database import IdaCommandOptions
from loguru import logger

from tenrec.main_thread import MainThreadExecutor
from tenrec.plugins.models import Instructions, PluginBase, operation
from tenrec.plugins.plugin_manager import PluginManager
from tenrec.sessions import Session


class Server(PluginBase):
    """Manages multiple IDA database sessions and coordinates plugin operations."""

    name = "server"
    version = "1.0.0"
    instructions = Instructions(
        purpose="Manages multiple IDA database sessions and coordinates plugin operations.",
        interaction_style=[
            "Be concise. Prefer bullet points. Show short code in fenced blocks with language hints.",
            "Always specify addresses in hexadecimal format (e.g., '0x401000').",
            "Once you have a session, you will want to begin your analysis.",
            (
                "Identify key functions using the `functions` plugin, focusing on the start "
                "function identified by IDA, as well as other functions of interest."
            ),
            (
                "From the functions, generate pseudo-code, and identify function "
                "calls and cross-references using the `xrefs` plugin."
            ),
            "Rename global and local variables using the `names` plugin to rename them to meaningful names.",
            (
                "Annotate functions, variables, and code blocks with "
                "comments using the `comments` plugin to provide context and explanations."
            ),
            (
                "Do NOT guess addresses or fabricate disassembly. "
                "If unsure, ask for a clarifying address or use the plugins provided."
            ),
        ],
        examples=[
            "Create a new session: `server_new_session(file='path/to/binary')`",
            "List all sessions: `server_list_sessions()`",
            "Switch to a session: `server_set_session(session_id='session_id')`",
            "Remove a session: `server_remove_session(session_id='session_id')`",
        ],
        anti_examples=[
            "DON'T attempt to analyze or modify the database directly.",
            "DON'T guess addresses or fabricate disassembly.",
        ],
    )

    def __init__(
        self,
        plugins: list[PluginBase],
        transport: Transport = "stdout",
        instructions: Instructions | None = None,
    ) -> None:
        plugins = [self, *plugins]
        self._transport = transport
        self._sessions: dict[str, Session] = {}
        self._current_session: str = ""

        if instructions:
            self.instructions = instructions

        # IDA monkey patches
        self.apply_monkey_patches()

        # Initialize plugin manager
        self.plugin_manager = PluginManager(plugins)

        # Initialize MCP server
        self.mcp = FastMCP(self.name, instructions=self.plugin_manager.instructions)

        logger.info("Registered {} plugins", len(plugins))

    def run(self, **transport_kwargs: Any) -> None:
        self.plugin_manager.register_plugins(self.mcp)
        logger.info("Registered {} tools", self.plugin_manager.tools_registered)

        executor = MainThreadExecutor.instance()

        def _run_server():
            try:
                self.mcp.run(transport=self._transport, **transport_kwargs)
            finally:
                # When the MCP transport closes (client disconnect, EOF, etc.)
                # stop the main-thread executor so the process can exit.
                executor.stop()

        # Run FastMCP server in a background daemon thread so the main thread
        # stays free to service IDA API calls (which require the main thread).
        server_thread = threading.Thread(target=_run_server, daemon=True)
        server_thread.start()

        # Block the main thread, processing IDA work items until the server
        # thread exits (client disconnect / transport close).
        try:
            executor.run_forever()
        except KeyboardInterrupt:
            executor.stop()
        finally:
            server_thread.join(timeout=5)

    @operation()
    def new_session(
        self,
        file: str,
        options: IdaCommandOptions | None = None,
    ) -> dict:
        """Creates a new session from the given file.

        :param file: The file to create the session from.
        :param options: The options to use for the session.
        :return: Session metadata.
        :raises ValueError: If a session for the given file already exists.
        """
        if not options:
            options = IdaCommandOptions(auto_analysis=True)

        for s in self._sessions.values():
            if s.file == file:
                msg = f"Session for {file} already exists"
                raise ValueError(msg)

        # Close the current session if one is open
        if self._current_session != "":
            current_session = self._sessions.get(self._current_session)
            if current_session and current_session.database.is_open():
                current_session.database.close()

        session = Session(file, options)
        self._sessions[session.id] = session
        self.update_session_id(session.id)
        session.database.open(analyze=True, force=True)
        logger.info("Created new session {} for file {}", session.id, file)
        return session.__dict__

    @operation()
    def list_sessions(self) -> dict[str, list[Any]]:
        """List all sessions.

        :return: A list of session metadata.
        """
        result = []
        for session in self._sessions.values():
            result.append(session.__dict__)
        return {"result": result}

    @operation()
    def set_session(self, session_id: str) -> dict:
        """Open the given session.

        :param session_id: The id of the session to open.
        :return: Session metadata.
        :raises KeyError: If the session does not exist.
        """
        # Check if the session exists
        session = self._sessions.get(session_id)
        if not session:
            msg = f"Session {session_id} not found"
            raise KeyError(msg)

        # Close the current session if one is open
        if self._current_session not in ("", session_id):
            current_session = self._sessions.get(self._current_session)
            if current_session and current_session.database.is_open():
                current_session.database.close()

        # Open the new session
        self.update_session_id(session_id)
        if not session.database.is_open():
            session.database.open(analyze=False, force=True)
        logger.info("Switched to session {} for file {}", session.id, session.file)
        return session.__dict__

    @operation()
    def remove_session(self, session_id: str) -> bool:
        """Remove the given session.

        :param session_id: The id of the session to close.
        :return: True if the session was removed, False otherwise.
        :raises KeyError: If the session does not exist.
        """
        session = self._sessions.pop(session_id, None)
        if not session:
            msg = f"Session {session_id} not found"
            raise KeyError(msg)

        session.database.close()
        if self._current_session == session_id:
            self.update_session_id("")
        logger.info("Removed session {} for file {}", session.id, session.file)
        return True

    @operation()
    def remove_all_sessions(self) -> None:
        """Remove all sessions."""
        for s in list(self._sessions.values()):
            s.database.close()
        self._sessions.clear()
        self.update_session_id("")
        logger.info("Removed all sessions")

    def update_session_id(self, session_id: str) -> None:
        """Update the current session id and plugin database."""
        self._current_session = session_id
        session = self._sessions.get(session_id)
        if session:
            self.plugin_manager.set_database(session.database.database)

    @staticmethod
    def apply_monkey_patches() -> None:
        from ida_domain.strings import StringType  # noqa: PLC0415

        StringType.__str__ = lambda s: s.name
