import uuid

from ida_domain.database import IdaCommandOptions

from tenrec.plugins.database_manager import DatabaseHandler, Status


class Session:
    def __init__(self, file: str, options: IdaCommandOptions) -> None:
        self._id = str(uuid.uuid4())
        self._file = file
        self._options = options
        self._database = DatabaseHandler(path=file, args=options)

    @property
    def id(self) -> str:
        return self._id

    @property
    def file(self) -> str:
        return self._file

    @property
    def options(self) -> IdaCommandOptions:
        return self._options

    @property
    def database(self) -> DatabaseHandler:
        return self._database

    @property
    def status(self) -> Status:
        return self._database.status

    @property
    def __dict__(self) -> dict:
        return {
            "id": self._id,
            "file": self._file,
            "options": self._options.__dict__,
            "status": self._database.status.name,
        }
