import importlib
import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Any

import giturlparse
from git import Repo
from giturlparse import GitUrlParsed
from loguru import logger
from pydantic import BaseModel, ConfigDict

from tenrec.plugins.models import PluginBase
from tenrec.utils import PREFIX, console, plugin_path

PLUGIN_VAR = "plugin"


class LoadedPlugin(BaseModel):
    """Represents a loaded plugin."""

    path: Path
    git: str | None = None
    plugin: PluginBase
    model_config = ConfigDict(arbitrary_types_allowed=True)


def load_plugins(paths: list) -> list[LoadedPlugin]:
    """Load plugins from the given paths."""
    plugins = []

    for plugin in list(paths):
        objs = _load(plugin)
        if all(isinstance(p.plugin, PluginBase) for p in objs):
            plugins.extend(objs)

    return plugins


def _parse_github_url(url: GitUrlParsed, plugin_string: str) -> tuple[Path, bool]:
    success = True
    branch = None
    subdir = None
    if "#" in plugin_string:
        plugin_string, params = plugin_string.split("#", 1)
        if params:
            for param in params.split("&"):
                key, _, value = param.partition("=")
                if not key or not value:
                    continue
                if key in {"branch", "tag", "commit"}:
                    branch = value
                elif key == "subdir":
                    subdir = value
                else:
                    continue

    def _should_clone(p: Path) -> bool:
        if p.exists():
            logger.warning("The path to the plugin already exists!")
            choice = console.input(
                PREFIX["WARNING"] + f" Would you like to re-clone [dim]{url.name}[/]? (y/N): "
            ).lower()
            if choice != "y":
                logger.info("Got it! Skipping re-clone.")
                return False
            shutil.rmtree(p)
        return True

    path = plugin_path()
    path = path / url.user / url.name

    try:
        if _should_clone(path):
            path.mkdir(parents=True, exist_ok=True)
            Repo.clone_from(plugin_string, path)

        if branch:
            repo = Repo(path)
            repo.git.checkout(branch)
        if subdir:
            path = path / subdir
            if not path.exists() or not path.is_dir():
                logger.error(
                    "Subdirectory [dim]{}[/] does not exist in the repository [dim]{}[/]", subdir, plugin_string
                )
                success = False
    except Exception as e:
        logger.error("Failed to clone plugin from [dim]{}[/]:\n---\n[bold red]{}[/]\n---", plugin_string, e)
        success = False
    return path, success


def _load(plugin_string: str) -> list[LoadedPlugin]:
    """Load and return the plugin."""
    parsed = giturlparse.parse(plugin_string)
    if parsed.valid:
        logger.info("Cloning plugin from git repository: [dim]{}[/]", plugin_string)
        path, success = _parse_github_url(parsed, plugin_string)
        if not success:
            return []
    else:
        path = Path(plugin_string)
        if not path.exists(follow_symlinks=True):
            logger.error("Plugin path does not exist: [dim]{}[/]", plugin_string)
            return []

    def _load_helper(load_path: Path) -> LoadedPlugin | None:
        if _is_file_path(load_path):
            try:
                p = _load_from_file(load_path)
                if not p:
                    return None
                res = LoadedPlugin(path=load_path, plugin=p)
                if parsed.valid:
                    res.git = plugin_string
                return res
            except (ImportError, FileNotFoundError, AttributeError) as e:
                logger.error("Failed to load plugin from file [dim]{}[/]:\n\t[red]{}[/]", load_path, e)
                return None
        return None

    if path.is_file():
        result = _load_helper(path)
        if result:
            return [result]
        return []

    if path.is_dir():
        loaded = []
        for file in path.glob("*.py"):
            result = _load_helper(file)
            logger.debug("Loaded plugin from file: {}", file)
            if result:
                loaded.append(result)
        return loaded

    msg = f"Invalid plugin path: {plugin_string}"
    raise ValueError(msg)


def _is_file_path(module: Path) -> bool:
    """Check if module string is a file path."""
    return module.exists() and module.is_file() and module.name.endswith(".py")


def _load_from_file(path: Path) -> "PluginBase":
    """Load a plugin module from file path with proper package context."""
    logger.debug("Attempting to load plugin from file: {}", path)

    if not path.exists():
        msg = f"Plugin file not found: {path}"
        logger.debug("{}", msg)
        raise FileNotFoundError(msg)

    # Skip package initializers as plugins
    if path.name == "__init__.py":
        logger.debug("Skipping package initializer: {}", path)
        raise ImportError(f"Not a plugin module (package initializer): {path}")

    # Walk up while __init__.py exists to collect package parts (inner -> outer)
    pkg_parts: list[str] = []
    pkg_dir = path.parent
    while (pkg_dir / "__init__.py").exists():
        pkg_parts.append(pkg_dir.name)
        pkg_dir = pkg_dir.parent

    # Insert the directory ABOVE the topmost package (import root)
    import_root = str(pkg_dir)
    if import_root not in sys.path:
        sys.path.insert(0, import_root)
        logger.debug("Inserted import root into sys.path: {}", import_root)
    else:
        logger.debug("Import root already in sys.path: {}", import_root)

    # Build fully-qualified module name correctly: outer...inner.<stem>
    if pkg_parts:
        package_fq = ".".join(reversed(pkg_parts))  # e.g. tenrec.plugins.plugins
        module_name = f"{package_fq}.{path.stem}"  # e.g. tenrec.plugins.plugins.functions
    else:
        package_fq = None
        module_name = f"_plugin_{path.stem}"

    logger.debug(
        "Resolved module name: {} (pkg_parts={}, import_root={})", module_name, list(reversed(pkg_parts)), import_root
    )

    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        msg = f"Could not load module spec from {path}"
        logger.debug("{}", msg)
        raise ImportError(msg)

    module = importlib.util.module_from_spec(spec)

    # Set __package__ and pre-import parent package so relative imports work
    if package_fq:
        module.__package__ = package_fq
        logger.debug("Set module.__package__ to: {}", module.__package__)
        try:
            importlib.import_module(package_fq)
            logger.debug("Pre-imported parent package: {}", package_fq)
        except Exception as e:
            msg = f"Failed to import parent package '{package_fq}' for {path}: {e}"
            logger.debug("{}", msg)
            raise ImportError(msg) from e
    else:
        logger.debug("Module has no package; using top-level name: {}", module_name)

    # Register before exec so intra-package imports can see it
    sys.modules[module_name] = module

    try:
        logger.debug("Executing module: {}", module_name)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception as e:
        sys.modules.pop(module_name, None)
        msg = f"Failed to execute {path}: {e}"
        logger.debug("{}", msg)
        raise ImportError(msg) from e

    if not hasattr(module, PLUGIN_VAR):
        sys.modules.pop(module_name, None)
        msg = (
            f"Plugin variable '{PLUGIN_VAR}' not found in module {module_name} "
            f"({path}). Ensure the file defines `{PLUGIN_VAR}`."
        )
        logger.debug("{}", msg)
        raise ImportError(msg)

    plugin = getattr(module, PLUGIN_VAR)
    logger.debug("Successfully loaded plugin '{}' from {}", PLUGIN_VAR, path)
    return plugin


def _load_from_import(module: Path) -> Any:
    """Load module using standard import."""
    return importlib.import_module(str(module.absolute()))
