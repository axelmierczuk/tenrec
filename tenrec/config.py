import sys
from pathlib import Path
from typing import Dict, Tuple, List

from pydantic import BaseModel, PrivateAttr

from tenrec.installer import Installer
from tenrec.plugins.plugin_loader import load_plugins
from loguru import logger

from tenrec.utils import config_path


class Plugin(BaseModel):
    name: str
    description: str | None = None
    version: str
    location: str
    git: str | None = None


class Config(BaseModel):
    plugins: List[Plugin] = []

    # --- internal snapshot of initial/last-saved state ---
    _snapshot: Dict[str, dict] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context) -> None:
        self._snapshot = self._fingerprint()

    @classmethod
    def load_config(cls) -> "Config":
        cfg_file = config_path()
        if cfg_file.exists() and cfg_file.is_file():
            obj = cls.model_validate_json(cfg_file.read_text(encoding="utf-8"))
        else:
            cfg_file.parent.mkdir(parents=True, exist_ok=True)
            obj = cls()
            cfg_file.write_text(obj.model_dump_json(indent=2), encoding="utf-8")
        # ensure snapshot matches what we loaded/wrote
        obj._snapshot = obj._fingerprint()
        return obj

    @property
    def config_path(self) -> Path:
        return config_path()

    @property
    def plugin_paths(self) -> list[str]:
        return [p.location for p in self.plugins]

    # --- helpers: fingerprint + diff ---
    def _fingerprint(self) -> Dict[str, dict]:
        """
        Create a stable, comparable representation of the config.
        We key plugins by name and dump their fields (excluding Nones).
        """
        fp: Dict[str, dict] = {}
        for p in self.plugins:
            fp[p.name] = p.model_dump(exclude_none=True)
        return fp

    def _diff(self) -> Tuple[List[Plugin], List[Plugin], List[Tuple[Plugin, Plugin]]]:
        """
        Returns (added, removed, updated) where:
          - added: plugins present now but not in snapshot
          - removed: plugins present in snapshot but not now
          - updated: (old, new) pairs where fields changed
        """
        current = self._fingerprint()
        prev = self._snapshot

        added_names = current.keys() - prev.keys()
        removed_names = prev.keys() - current.keys()
        common = current.keys() & prev.keys()

        added = [Plugin(**current[n]) for n in sorted(added_names)]
        removed = [Plugin(**prev[n]) for n in sorted(removed_names)]

        updated: List[Tuple[Plugin, Plugin]] = []
        for n in sorted(common):
            if current[n] != prev[n]:
                updated.append((Plugin(**prev[n]), Plugin(**current[n])))

        return added, removed, updated

    def _on_change(
        self,
        added: List[Plugin],
        removed: List[Plugin],
        updated: List[Tuple[Plugin, Plugin]],
    ) -> None:
        """
        Place extra processing here. Examples:
          - clone/pull git plugins when added/updated
          - purge plugin directories when removed
          - trigger in-memory reloads, cache busts, etc.
        """
        if len(added) != 0 or len(removed) != 0 or len(updated) != 0:
            plugins = load_plugins(paths=self.plugin_paths)
            logger.info("Detected changes to plugins, running installer to update auto-approve tools")
            Installer(plugins=[p.plugin for p in plugins]).install()

    def save_config(self) -> None:
        added, removed, updated = self._diff()
        if added or removed or updated:
            self._on_change(added, removed, updated)
        self.config_path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        self._snapshot = self._fingerprint()
