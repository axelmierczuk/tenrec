import builtins
import sys
import warnings
from pathlib import Path

from rich.console import Console


_original_print = builtins.print
_original_showwarning = warnings.showwarning

PREFIX = {
    "DEBUG": "[dim][*][/]",
    "INFO": "[bold blue][*][/]",
    "SUCCESS": "[bold green][+][/]",
    "WARNING": "[bold yellow][!][/]",
    "ERROR": "[bold red][X][/]",
    "FAILURE": "[bold red][X][/]",
    "CRITICAL": "[bold red][X][/]",
}


def disable_print() -> None:
    """Disable the built-in print function."""
    builtins.print = lambda *a, **k: None


def enable_print() -> None:
    """Enable the built-in print function."""
    builtins.print = _original_print


def diable_warnings() -> None:
    """Disable warnings."""
    warnings.showwarning = lambda *a, **k: None  # noqa: ARG005


def enable_warnings() -> None:
    """Enable warnings."""
    warnings.showwarning = _original_showwarning


console = Console(stderr=True)


def rich_sink(message) -> None:  # noqa: ANN001
    r = message.record
    prefix = PREFIX.get(r["level"].name, "[*]")
    console.print(f"{prefix} {r['message']}", highlight=False)
    if r["exception"]:
        console.print_exception()


def config_path() -> Path:
    """Return the path to the config file."""
    home = Path.home()
    if sys.platform == "win32":
        prefix = home / "AppData" / "Roaming"
    elif sys.platform in {"darwin", "linux"}:
        prefix = home / ".config"
    else:
        raise RuntimeError("Unsupported platform, cannot determine config path")
    return prefix / "tenrec" / "config.json"


def plugin_path() -> Path:
    path = config_path().parent / "plugins"
    path.mkdir(exist_ok=True)
    return path
