import threading
from enum import IntEnum

from ida_domain.database import Database, DatabaseMetadata, IdaCommandOptions

from tenrec.plugins.models import operation


class Status(IntEnum):
    WAITING = 0
    OPENING = 1
    READY = 2
    CLOSING = 3
    CLOSED = 4


class DatabaseHandler:
    def __init__(self, path: str, args: IdaCommandOptions) -> None:
        self._lock = threading.RLock()
        self._path = path
        self._args = args
        self._database = Database()
        self._status = Status.CLOSED

    def open(self, analyze: bool = True, force: bool = False) -> None:
        # Analyze by default, but can override
        with self._lock:
            if not self._database.is_open():
                self._status = Status.OPENING
                # If analyze is False, disable auto_analysis regardless of args
                # If analyze is True, use the value from args
                auto_analysis = analyze if force else analyze and self._args.auto_analysis
                args = self._args.__dict__
                args["auto_analysis"] = auto_analysis
                args = IdaCommandOptions(**args)
                self._database.open(self._path, args, save_on_close=True)
                self._status = Status.READY

    def close(self) -> None:
        with self._lock:
            if self._database.is_open():
                self._status = Status.CLOSING
                self._database.close(save=True)
                self._status = Status.CLOSED

    def is_open(self) -> bool:
        with self._lock:
            return self._database.is_open()

    @property
    def database(self) -> Database:
        return self._database

    @property
    def status(self) -> Status:
        return self._status

    @operation()
    def metadata(self) -> DatabaseMetadata:
        """Retrieves metadata from the database.

        :return: The metadata from the database.
        """
        return self._database.metadata
