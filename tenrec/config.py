import json
import os
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field, PrivateAttr, model_validator

from tenrec.installer import Installer
from tenrec.plugins.plugin_loader import LoadedPlugin, load_plugin_by_dist_ep, load_plugins
from tenrec.utils import config_path, console


class Config(BaseModel):
    """Configuration for tenrec, including installed plugins.

    The config file works by providing an abstraction layer between what's stored on disk, and
    loaded in memory. The `plugins` field is a dict of `LoadedPlugin` objects, which include
    the actual plugin instance loaded from the specified location. The `Plugin` model is used
    for serialization/deserialization to/from JSON.
    """

    plugins: dict[str, LoadedPlugin] = Field(default_factory=dict)
    load_failures: dict[str, dict] = Field(default_factory=dict)
    load_failures_exist: bool = False
    _snapshot: "Config | None" = PrivateAttr(default_factory=lambda: None)

    """
    Client properties and methods
    --------------------------
    These are used by the client to load/save the config, and manage plugins.
    The `load_config` method will attempt to load the config from disk, and if it doesn't exist,
    it will create a default config file. If any plugins fail to load, the user will be prompted
    to remove them from the config. If the user chooses not to remove them, they will remain in the config
    and be attempted to be loaded again on the next run.

    The `save_config` method will save the config to disk, and if there are any changes to the plugins,
    it will trigger the installer to re-run to update any auto-approve tools.

    The `add_plugins` and `remove_plugins` methods are used to manage the list of plugins in the config.
    """

    @classmethod
    def load_config(cls) -> "Config":
        cfg_file = config_path()
        if cfg_file.exists() and cfg_file.is_file():
            # `load_plugins_validator` will be called automatically
            obj = cls.model_validate_json(cfg_file.read_text(encoding="utf-8"))
        else:
            # Create a default config file
            cfg_file.parent.mkdir(parents=True, exist_ok=True)
            obj = cls(plugins={})
            cfg_file.write_text(obj.model_dump_json(indent=2), encoding="utf-8")
        return obj

    def save_config(self) -> None:
        added, removed, updated = self._diff()
        if added or removed or updated:
            self._on_change(added, removed, updated)
        self.config_path.write_text(json.dumps(self.model_dump(), indent=2), encoding="utf-8")
        self._snapshot = self._fingerprint()

    def add_plugins(self, plugins: list[str]) -> int:
        loaded, errors = load_plugins(plugins)
        if len(errors) != 0:
            return len(errors)

        added = 0
        for name, plugin in loaded.items():
            if name in self.plugins:
                logger.warning("Plugin with name '{}' already exists, skipping.", name)
                continue
            self.plugins[name] = plugin
            added += 1
        return added

    def remove_plugins(self, dists: list[str]) -> int:
        removed = 0
        for dist in dists:
            to_remove = []
            for plugin in self.plugins.values():
                if plugin.dist_name != dist:
                    continue
                to_remove.append(plugin.name)

            if len(to_remove) == 0:
                logger.warning("Plugins with dist '{}' does not exist, skipping.", dist)
                continue

            cmd = ["uv", "pip", "uninstall", dist]
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )

            for name in to_remove:
                del self.plugins[name]
                removed += 1
            logger.success("Removed plugins for: [dim]{}[/]", dist)
        return removed

    @property
    def config_path(self) -> Path:
        return config_path()

    """
    Change detection logic
    --------------------------
    We want to detect when the config has changed in a meaningful way, so we can trigger
    actions like re-running the installer to update auto-approve tools.
    """

    @staticmethod
    def _compare_plugins(p1: LoadedPlugin, p2: LoadedPlugin) -> bool:
        return p1.model_dump() == p2.model_dump()

    def _fingerprint(self) -> "Config":
        """Create a stable, comparable representation of the config.

        We key plugins by name and dump their fields (excluding Nones).
        """
        return deepcopy(self)

    def _diff(self) -> tuple[list[LoadedPlugin], list[LoadedPlugin], list[tuple[LoadedPlugin, LoadedPlugin]]]:
        current = self._fingerprint().plugins
        prev = self._snapshot
        if prev is None:
            return list(current.values()), [], []
        prev = prev.plugins

        added_names = current.keys() - prev.keys()
        removed_names = prev.keys() - current.keys()
        common = current.keys() & prev.keys()

        added = [current[n] for n in sorted(added_names)]
        removed = [prev[n] for n in sorted(removed_names)]
        updated: list[tuple[LoadedPlugin, LoadedPlugin]] = []

        for n in sorted(common):
            if self._compare_plugins(prev[n], current[n]):
                continue
            updated.append((prev[n], current[n]))
        logger.debug("Config diff - added: {}, removed: {}, updated: {}", len(added), len(removed), len(updated))
        return added, removed, updated

    def _on_change(
        self,
        added: list[LoadedPlugin],
        removed: list[LoadedPlugin],
        updated: list[tuple[LoadedPlugin, LoadedPlugin]],
    ) -> None:
        _ = added, removed, updated
        self._run_installer()

    def _run_installer(self) -> None:
        logger.info("Running installer to update auto-approve tools")
        Installer(plugins=[p.plugin for p in self.plugins.values()]).install()

    """
    Pydantic model methods
    --------------------------
    These are used by pydantic to serialize/deserialize the config to/from JSON.
    """

    def model_dump(self, **kwargs: dict[str, Any]) -> dict[str, Any]:  # noqa: ARG002
        result = {}

        def _dump_plugins(plugin_dict: dict[str, LoadedPlugin]) -> dict[str, dict]:
            return {name: p.model_dump() for name, p in plugin_dict.items()}

        plugins = _dump_plugins(self.plugins)
        result["plugins"] = plugins | self.load_failures
        return result

    def model_post_init(self, __context) -> None:  # noqa: ANN001, PYI063
        self._snapshot = self._fingerprint()

    @model_validator(mode="before")
    def load_plugins_validator(cls, values: dict) -> dict:  # noqa: N805
        values["load_failures"] = {}
        plugins = {}

        for p in values["plugins"].values():
            name = p.get("name")
            dist_name = p.get("dist_name")
            ep_name = p.get("ep_name")
            if not name or not dist_name or not ep_name:
                logger.warning("Skipping invalid plugin entry in config: {}", p)
                continue
            try:
                logger.debug("Loading plugin '{}' from {}:{}", name, dist_name, ep_name)
                plugin_obj = load_plugin_by_dist_ep(dist_name, ep_name)
                plugins[name] = {**p, "plugin": plugin_obj}
            except (RuntimeError, ImportError, ValueError):
                values["load_failures"][name] = p

        values["plugins"] = plugins
        num_fail = len(values["load_failures"])
        if num_fail == 0:
            return values

        values["load_failures_exist"] = True

        plural = "" if num_fail == 1 else "s"
        msg = f"[red]{num_fail} plugin{plural} failed to load[/], would you like to remove them from the config? (y/N) "
        choice = console.input(msg).lower()
        if choice == "y":
            values["load_failures"] = {}
            return values

        logger.info("Fair enough! They'll remain in your config.")
        return values

    @model_validator(mode="after")
    def validate_load_failure_purge(self) -> "Config":
        if len(self.load_failures) == 0 and self.load_failures_exist:
            self.save_config()
            # Forced to re-run installer if any plugins were removed
            self._run_installer()
        return self
