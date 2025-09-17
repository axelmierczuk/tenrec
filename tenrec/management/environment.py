import os
from pathlib import Path

from pydantic import BaseModel


env = None


class EnvironmentVariables(BaseModel):
    debug: bool = False
    ida: Path

    @classmethod
    def load_vars(cls) -> "EnvironmentVariables":
        debug = False
        ida = None
        if ida_path := os.getenv("IDADIR", None):
            ida = Path(ida_path)
        else:
            msg = "Environment variable IDADIR is not set. Please set it to the IDA Pro installation directory."
            raise RuntimeError(msg)

        if not ida.exists() or not ida.is_dir():
            msg = f"Invalid IDA path from IDADIR environment variable: {ida}"
            raise RuntimeError(msg)

        if os.getenv("DEBUG", None):
            debug = True

        return cls(debug=debug, ida=ida)


def load_environment() -> EnvironmentVariables:
    """Load environment variables and return an EnvironmentVariables instance."""
    return EnvironmentVariables.load_vars()


def get_environment() -> EnvironmentVariables:
    """Get the loaded environment variables."""
    global env
    if env is None:
        env = load_environment()
    return env
