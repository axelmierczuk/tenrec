import os
import site
import subprocess
import sys
from pathlib import Path

from pydantic import BaseModel

from tenrec.utils import get_venv_path


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

        venv = get_venv_path()
        if venv.exists() and not venv.is_dir():
            msg = f"Virtual environment path exists but is not a directory: {venv}"
            raise RuntimeError(msg)

        if not venv.exists():
            cmd = ["uv", "venv", str(venv)]
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )

        plugin_site = (
            get_venv_path() / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        )
        site.addsitedir(str(plugin_site))
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
