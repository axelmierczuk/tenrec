# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator
from importlib.metadata import Distribution, PackageNotFoundError, distribution, distributions, entry_points
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, ConfigDict

from tenrec.plugins.models import PluginBase
from tenrec.utils import get_venv_path


EP_GROUP = "tenrec.plugins"


class LoadedPlugin(BaseModel):
    """Represents a loaded plugin discovered via entry points."""

    name: str
    description: str | None = None
    version: str
    dist_name: str
    ep_name: str
    plugin: PluginBase

    def model_dump_json(self, **kwargs: Any) -> str:
        return json.dumps(self.model_dump(**kwargs), indent=2)

    def model_dump(self, **kwargs: Any) -> dict:  # noqa: ARG002
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "dist_name": self.dist_name,
            "ep_name": self.ep_name,
        }

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ---------- install/discovery utilities ----------


def _is_git_url(spec: str) -> bool:
    s = spec.lower()
    return s.startswith(("git+", "ssh://", "git://")) or s.endswith(".git")


def _is_local_dir(spec: str) -> bool:
    try:
        p = Path(spec).expanduser().resolve()
    except Exception:
        return False
    return p.exists() and p.is_dir()


def _install_with_uv(spec: str, editable: bool = False) -> list[str]:
    """Install 'spec' with uv and return newly added distributions' names."""
    before = {d.metadata["Name"] for d in distributions()}

    logger.info("Installing plugin spec via python: {}", spec)
    base = ["uv", "pip", "install"]
    cmd = [*base, spec]
    subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        cwd=get_venv_path().parent,
        env=os.environ.copy(),
    )

    after = {d.metadata["Name"] for d in distributions()}
    new = sorted(after - before)
    if not new:
        # nothing new detected; spec may have been an upgrade or already present
        logger.debug("No new distributions detected after install.")
    else:
        logger.debug("New distributions detected: {}", ", ".join(new))
    return new


def _discover_eps_for_dists(dist_names: list[str]) -> list[tuple[str, str]]:
    """Return list of (dist_name, ep_name) pairs for EP_GROUP limited to given dist_names.

    If dist_names is empty, return all (dist_name, ep_name) pairs.
    """
    eps = entry_points().select(group=EP_GROUP)
    # Python 3.12+ ep has .dist; for older versions we’ll match post-load
    pairs: list[tuple[str, str]] = []
    for ep in eps:
        dn = getattr(getattr(ep, "dist", None), "metadata", {}).get("Name")  # type: ignore[attr-defined]
        if dn:
            if not dist_names or dn in dist_names:
                pairs.append((dn, ep.name))
        # if we can’t see dist now, we’ll allow it only when dist_names is empty
        elif not dist_names:
            pairs.append(("<unknown>", ep.name))
    return pairs


def _load_ep(dist_name: str, ep_name: str) -> Iterator[LoadedPlugin | None]:
    # locate the entry point again (filtered)
    matches = entry_points().select(group=EP_GROUP, name=ep_name)
    if not matches:
        logger.error("Entry point '{}' not found in group '{}'.", ep_name, EP_GROUP)
        yield None
        return

    for match in matches:
        ep = match

        # load target
        try:
            target = ep.load()
        except Exception as e:
            logger.error("Failed to import entry point [dim]{}[/]: {}", ep_name, e)
            yield None
            continue

        # instantiate if callable
        try:
            obj = target() if callable(target) else target
        except Exception as e:
            logger.error("Failed to instantiate plugin for [dim]{}[/]: {}", ep_name, e)
            yield None
            continue

        if not isinstance(obj, PluginBase):
            logger.error(
                "Entry point [dim]{}[/] did not yield a PluginBase (got: {}).",
                ep_name,
                type(obj).__name__,
            )
            yield None
            continue

        # resolve distribution metadata
        resolved_dist_name = dist_name
        if resolved_dist_name in ("", "<unknown>", None):
            # Best-effort: try to find which dist provides the module via importlib.metadata
            try:
                # ep.module is available on 3.12; otherwise rely on ep value fallback
                # We can try reading distribution from plugin's package
                mod = obj.__class__.__module__.split(".")[0]
                resolved_dist_name = distribution(mod).metadata["Name"]  # type: ignore[arg-type]
            except Exception:
                resolved_dist_name = "<unknown>"

        # metadata fallbacks
        dist_obj: Distribution | None = None
        try:
            if resolved_dist_name not in ("<unknown>",):
                dist_obj = next((d for d in distributions() if d.metadata["Name"] == resolved_dist_name), None)
        except Exception:
            dist_obj = None

        dist_version = dist_obj.version if dist_obj else None  # type: ignore[assignment]
        dist_summary = (dist_obj.metadata.get("Summary") if dist_obj else None) or None  # type: ignore[union-attr]

        plugin_name = getattr(obj, "name", ep_name)
        plugin_version = getattr(obj, "version", None) or dist_version or "0.0.0"
        plugin_desc = getattr(obj, "__doc__", None) or dist_summary
        if isinstance(plugin_desc, str):
            plugin_desc = plugin_desc.strip() or None

        yield LoadedPlugin(
            name=plugin_name,
            description=plugin_desc,
            version=str(plugin_version),
            dist_name=str(resolved_dist_name),
            ep_name=ep_name,
            plugin=obj,
        )


def load_plugins(paths: list[str]) -> tuple[dict[str, LoadedPlugin], list[str]]:
    """Install and load plugins from a list of specs.

    Available spec types:
      - Local directories (installed editable with uv)
      - Git repos (e.g., git+https://..., ssh://git@..., ...; supports #subdirectory=)
      - Package specs (PyPI names, with optional versions/extras)

    Returns:
        (plugins_by_name, load_failures)
    """
    plugins: dict[str, LoadedPlugin] = {}
    failures: list[str] = []

    for spec in list(paths):
        new_dists: list[str] = []
        try:
            if _is_local_dir(spec):
                # local dir → editable install
                new_dists = _install_with_uv(str(Path(spec).resolve()), editable=True)
            elif _is_git_url(spec):
                # git URL → normal install; uv supports refs/subdirectory via standard pip URL fragment
                new_dists = _install_with_uv(spec)
            else:
                # registry/package spec → normal install (or upgrade/no-op)
                new_dists = _install_with_uv(spec)
        except subprocess.CalledProcessError as e:
            logger.error("Failed to install spec [dim]{}[/]: {}", spec, e.stderr or e.stdout or e)
            failures.append(spec)
            continue
        except Exception as e:
            logger.error("Unexpected error installing [dim]{}[/]: {}", spec, e)
            failures.append(spec)
            continue

        # Discover EPs belonging to new distributions.
        pairs = _discover_eps_for_dists(new_dists)

        # If we didn't detect new dists (already installed), try to find EPs by name match heuristic:
        if not pairs:
            # Heuristic: look for EPs whose name equals the spec (without extras/version),
            # or just load all EPs and let PluginBase validation filter.
            pairs = _discover_eps_for_dists([])

        # Load each EP and collect results (only add once per plugin name)
        for dist_name, ep_name in pairs:
            any_loaded_for_spec = False

            for loaded in _load_ep(dist_name, ep_name):
                if loaded is None:
                    continue
                # Only count EPs that plausibly came from this spec:
                if new_dists and loaded.dist_name not in new_dists:
                    # skip EPs from unrelated distributions when we have a clear set
                    continue
                if loaded.name in plugins:
                    logger.warning("Plugin with name '{}' already loaded, skipping duplicate.", loaded.name)
                    continue

                plugins[loaded.name] = loaded
                any_loaded_for_spec = True

            if not any_loaded_for_spec:
                logger.error(
                    "No '{}' entry points were found after installing [dim]{}[/]. "
                    'Ensure the package declares [project.entry-points."{}"].',
                    EP_GROUP,
                    spec,
                    EP_GROUP,
                )
                failures.append(spec)

    return plugins, failures


def _find_ep(dist_name: str, ep_name: str):
    """Return the matching entry point object for (dist_name, ep_name)."""
    # Prefer Python 3.12+ path: .dist is available on EntryPoint
    eps = entry_points().select(group=EP_GROUP, name=ep_name)
    for ep in eps:
        dn = getattr(getattr(ep, "dist", None), "metadata", {}).get("Name")  # type: ignore[attr-defined]
        if dn and dn == dist_name:
            return ep

    # Fallback: if .dist is unavailable, match by loading and checking module->distribution
    for ep in eps:
        try:
            target = ep.load()
            obj = target() if callable(target) else target
            mod_top = (obj.__class__.__module__ or "").split(".")[0]
            try:
                dn = distribution(mod_top).metadata["Name"]  # type: ignore[arg-type]
            except PackageNotFoundError:
                dn = None
            if dn == dist_name:
                return ep
        except Exception:
            continue
    return None


def load_plugin_by_dist_ep(dist_name: str, ep_name: str) -> PluginBase:
    """Load and instantiate the plugin specified by (dist_name, ep_name).

    Returns the PluginBase instance, or raises RuntimeError with a friendly message.
    """
    ep = _find_ep(dist_name, ep_name)
    if not ep:
        msg = f"Plugin entry point '{ep_name}' not found in distribution '{dist_name}'."
        raise RuntimeError(msg)

    try:
        target = ep.load()
    except Exception as e:
        msg = f"Failed to import entry point '{ep_name}' from '{dist_name}': {e}"
        raise RuntimeError(msg) from e

    try:
        plugin = target() if callable(target) else target
    except Exception as e:
        msg = f"Failed to instantiate plugin for '{dist_name}:{ep_name}': {e}"
        raise RuntimeError(msg) from e

    if not isinstance(plugin, PluginBase):
        msg = f"Entry point '{dist_name}:{ep_name}' did not return a PluginBase (got {type(plugin).__name__})."
        raise TypeError(msg)
    return plugin
