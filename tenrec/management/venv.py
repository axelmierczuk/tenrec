import contextlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from importlib.metadata import distributions
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from tenrec.management.utils import config_path


if TYPE_CHECKING:
    from collections.abc import Iterable


def _snapshot_paths(path: str) -> dict[str, tuple[str, str, list[str]]]:
    """Scan exactly the given site-packages paths (venv).

    returns: {canonical_name: (display_name, version, [canonical_requires...])}
    """
    snap: dict[str, tuple[str, str, list[str]]] = {}
    for d in distributions(path=[path]):
        name = d.metadata.get("Name")
        if not name:
            continue
        canon = canonicalize_name(name)
        ver = d.version or ""
        reqs_raw: Iterable[str] = d.requires or []
        reqs: list[str] = []
        for r in reqs_raw:
            with contextlib.suppress(Exception):
                reqs.append(canonicalize_name(Requirement(r).name))
        snap[canon] = (name, ver, reqs)
    return snap


class VenvManager:
    def __init__(self, temporary: bool = False) -> None:
        i = str(random.randint(1000000, 2000000))
        venv = Path(tempfile.gettempdir()) / f".tenrec-venv-{i}" if temporary else config_path().parent / ".venv"
        self._temporary = temporary
        self._venv = venv
        self._site = venv / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        self._python = venv / "bin" / "python"
        self._pre_sys_path: list[str] = []
        self._venv_sys_path: list[str] = []

    def _venv_paths(self) -> list[str]:
        # Ask the target interpreter for its full sys.path (includes stdlib)
        out = subprocess.check_output(
            [str(self._python), "-c", "import sys, json; print(json.dumps(sys.path))"],
            text=True,
        )
        return json.loads(out)

    def __enter__(self) -> "VenvManager":
        self._create_venv()
        self._pre_sys_path = list(sys.path)
        self._venv_sys_path = self._venv_paths()
        sys.path = self._venv_sys_path
        os.environ["VIRTUAL_ENV"] = str(self._venv)
        binary_dir = "Scripts" if os.name == "nt" else "bin"
        os.environ["PATH"] = str(self._venv / binary_dir) + os.pathsep + os.environ.get("PATH", "")

        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        sys.path = self._pre_sys_path
        os.environ.pop("VIRTUAL_ENV", None)
        # (Optionally restore PATH if you saved it)
        if self._temporary and self._venv.exists() and self._venv.is_dir():
            shutil.rmtree(self._venv)
        return False

    @property
    def venv(self) -> Path:
        return self._venv

    def _create_venv(self) -> None:
        if self._temporary:
            logger.info("Creating temporary virtual environment")
        if self._venv.exists() and not self._venv.is_dir():
            self._venv.unlink()

        if self._venv.exists() and self._temporary:
            shutil.rmtree(self._venv)

        if not self._venv.exists():
            cmd = ["uv", "venv", self._venv]
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )

    def install(self, spec: str) -> list[str]:
        """Install 'spec' with uv into self._python's venv and return the *root*.

        Returns newly-installed (or upgraded) distributions in that venv (not their deps)
        """
        logger.info("Installing plugin spec via uv: {}", spec)

        # Take snapshots strictly from the target venv paths
        before = _snapshot_paths(self._site)

        cmd = ["uv", "pip", "install", "--python", str(self._python), "--upgrade", "--reinstall", spec]
        logger.debug("Running install command: {}", " ".join(cmd))
        env = os.environ.copy()
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            cwd=self._venv.parent,
            env=env,
        )

        after = _snapshot_paths(self._site)

        before_names = set(before.keys())
        after_names = set(after.keys())

        # New names (fresh installs)
        new = after_names - before_names

        # If nothing new, consider upgraded ones (version changed)
        candidates = set(new)
        if not candidates:
            candidates = {n for n in (after_names & before_names) if before[n][1] != after[n][1]}

        if not candidates:
            logger.debug("No new or changed distributions detected.")
            return []

        # Among candidates, drop anything required by another candidate → keep roots
        required_by_candidates: set[str] = set()
        for n in candidates:
            _disp, _ver, reqs = after[n]
            for r in reqs:
                if r in candidates:
                    required_by_candidates.add(r)

        roots = sorted(candidates - required_by_candidates)
        roots_display = [after[n][0] for n in roots]
        logger.debug("Root distributions: {}", ", ".join(roots_display) or "(none)")
        return roots_display

    def uninstall(self, dist: str) -> None:
        logger.info("Uninstalling plugin spec via python: {}", dist)
        cmd = ["uv", "pip", "uninstall", "--python", str(self._python), dist]
        env = os.environ.copy()
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            cwd=self._venv.parent,
            env=env,
        )
