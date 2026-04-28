#!/usr/bin/env python3
"""Build C fixture binaries and generate IDA databases for integration tests.

Workflow:
    1. Configure + build the CMake project under ``build/`` (native targets).
    2. Build any Docker-based fixtures (sources/<name>/Dockerfile present)
       and extract the produced ELF binaries into ``binaries/``.
    3. Copy each produced native binary into ``binaries/``.
    4. For every binary, open it with ida-domain (which auto-analyses and
       writes a ``.i64`` next to the binary), then move the resulting
       database into ``databases/``.

Usage:
    IDADIR=/path/to/ida python tenrec/tests/fixtures/build_fixtures.py
    python tenrec/tests/fixtures/build_fixtures.py --skip-database  # binaries only
    python tenrec/tests/fixtures/build_fixtures.py --skip-docker    # native only
    python tenrec/tests/fixtures/build_fixtures.py --clean

The script is idempotent: re-running rebuilds incrementally and replaces
existing databases. Docker fixtures are skipped automatically when the
docker CLI isn't available — they're only required by the live-debugger
integration test, which has its own runtime guard.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parent
BUILD_DIR = ROOT / "build"
BINARIES_DIR = ROOT / "binaries"
DATABASES_DIR = ROOT / "databases"
SOURCES_DIR = ROOT / "sources"

# Companion files IDA produces alongside the .i64. These all need to move
# with the database, otherwise IDA will refuse to open it later.
IDA_SIDECAR_SUFFIXES = (".i64", ".id0", ".id1", ".id2", ".nam", ".til")

# Path inside a Docker fixture image where the built binary lives. Every
# Dockerfile under sources/<name>/ must place its compiled binary here so
# this orchestrator can extract it without per-target configuration.
DOCKER_BINARY_PATH = "/fixture/debugger"


def run(cmd: list[str]) -> None:
    """Run a subprocess, streaming output, raising on failure."""
    print(f"$ {' '.join(cmd)}")
    subprocess.check_call(cmd)


def configure_and_build(jobs: int | None) -> None:
    BUILD_DIR.mkdir(exist_ok=True)
    run(["cmake", "-S", str(ROOT), "-B", str(BUILD_DIR)])
    build_cmd = ["cmake", "--build", str(BUILD_DIR)]
    if jobs:
        build_cmd += ["--parallel", str(jobs)]
    else:
        build_cmd.append("--parallel")
    run(build_cmd)


def docker_available() -> bool:
    """Return True if a usable docker CLI is on PATH."""
    return shutil.which("docker") is not None


def docker_os_type() -> str | None:
    """Return the daemon's container OS type ("linux" or "windows"), or None."""
    if not docker_available():
        return None
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None


# Suffix-to-os mapping for fixture Dockerfile variants. A plain
# ``Dockerfile`` is Linux by convention; ``Dockerfile.windows`` is
# Windows-only. Adding a new platform = a new entry here.
_DOCKERFILE_OS_MAP: dict[str, str] = {
    "Dockerfile": "linux",
    "Dockerfile.windows": "windows",
}


def discover_docker_fixtures() -> list[tuple[Path, str, str]]:
    """Return ``(source_dir, dockerfile_name, os_type)`` for every fixture image.

    Each fixture source directory may host more than one Dockerfile (one
    per target OS). The orchestrator returns each variant separately so
    a Windows host can build the Windows variant while a Linux host
    builds the Linux variant — no per-host config required.
    """
    if not SOURCES_DIR.is_dir():
        return []
    out: list[tuple[Path, str, str]] = []
    for source_dir in sorted(p for p in SOURCES_DIR.iterdir() if p.is_dir()):
        for filename, os_type in _DOCKERFILE_OS_MAP.items():
            if (source_dir / filename).is_file():
                out.append((source_dir, filename, os_type))
    return out


def docker_fixture_image_tag(source_dir: Path) -> str:
    """Tag used for the docker image of a given fixture source dir."""
    return f"tenrec-fixture-{source_dir.name}"


def build_docker_fixtures() -> list[Path]:
    """Build each Docker-based fixture matching the daemon's OSType.

    Each ``sources/<name>/Dockerfile[.windows]`` must produce a binary
    at ``DOCKER_BINARY_PATH`` inside the image (forward slashes for Linux,
    ``C:/fixture/debugger.exe`` for Windows). We `docker build` the image,
    spin up a stopped container with `docker create`, copy the binary out
    with `docker cp`, then drop the container. The image is left around
    so the integration test can run it later without rebuilding.

    Variants targeting an OS the local daemon doesn't support are
    skipped with a clear message rather than failing the build — that's
    the cross-platform CI story (build linux fixtures on linux runners,
    windows fixtures on windows runners).
    """
    fixtures = discover_docker_fixtures()
    if not fixtures:
        return []
    if not docker_available():
        print("  docker CLI not found; skipping Docker fixtures.")
        return []

    daemon_os = docker_os_type()
    if daemon_os is None:
        print("  docker daemon unreachable; skipping Docker fixtures.")
        return []

    BINARIES_DIR.mkdir(exist_ok=True)
    out: list[Path] = []
    for source_dir, dockerfile, os_type in fixtures:
        tag = docker_fixture_image_tag(source_dir)
        if os_type != daemon_os:
            print(
                f"  skipping {source_dir.name}/{dockerfile}: daemon is "
                f"{daemon_os!r}, fixture targets {os_type!r}."
            )
            continue
        print(f"  building docker image {tag} from {source_dir.name}/{dockerfile}...")
        run([
            "docker", "build",
            "-f", str(source_dir / dockerfile),
            "-t", tag,
            str(source_dir),
        ])

        # `docker create` makes a container without starting it; perfect
        # for a one-shot copy. The container name is unique per fixture so
        # parallel builds don't collide.
        container = f"{tag}-extract"
        subprocess.run(
            ["docker", "rm", "-f", container],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        run(["docker", "create", "--name", container, tag])
        try:
            # Path inside the image where the binary lives — Linux uses
            # /fixture/debugger; Windows uses C:/fixture/debugger.exe.
            src_path = (
                "C:/fixture/debugger.exe"
                if os_type == "windows"
                else DOCKER_BINARY_PATH
            )
            target = BINARIES_DIR / source_dir.name
            run([
                "docker", "cp",
                f"{container}:{src_path}",
                str(target),
            ])
            target.chmod(0o755)
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        out.append(target)
        print(f"  -> {target.relative_to(ROOT)}")
    return out


def collect_binaries() -> list[Path]:
    """Copy newly built binaries into ``binaries/`` and return their paths."""
    BINARIES_DIR.mkdir(exist_ok=True)
    src = BUILD_DIR / "binaries"
    if not src.exists():
        msg = f"No binaries built at {src} — did the CMake build succeed?"
        raise RuntimeError(msg)

    out: list[Path] = []
    for binary in sorted(src.iterdir()):
        # Skip macOS debug bundles and non-executable artefacts.
        if binary.is_dir() or binary.suffix in {".dSYM", ".pdb"}:
            continue
        if not os.access(binary, os.X_OK):
            continue
        target = BINARIES_DIR / binary.name
        shutil.copy2(binary, target)
        out.append(target)
        print(f"  -> {target.relative_to(ROOT)}")
    if not out:
        msg = f"No executables found under {src}"
        raise RuntimeError(msg)
    return out


def generate_databases(binaries: list[Path]) -> None:
    """Use ida-domain to analyse each binary, then move the .i64 into databases/."""
    if not os.environ.get("IDADIR"):
        sys.exit(
            "IDADIR is not set. Point it at your IDA installation (e.g. "
            "'/Applications/IDA Professional 9.2.app/Contents/MacOS') or pass "
            "--skip-database."
        )

    # Import lazily so --skip-database works without IDA installed.
    from ida_domain import Database

    DATABASES_DIR.mkdir(exist_ok=True)

    for binary in binaries:
        # Strip any pre-existing database for this binary so we always get a
        # fresh, fully-analysed result.
        for suffix in IDA_SIDECAR_SUFFIXES:
            stale = binary.with_suffix(suffix)
            if stale.exists():
                stale.unlink()
            stale_target = DATABASES_DIR / stale.name
            if stale_target.exists():
                stale_target.unlink()

        print(f"  analysing {binary.name}...")
        with Database.open(str(binary), save_on_close=True) as db:
            # Touching metadata forces analysis to fully complete before close.
            _ = db.metadata

        # Move every sidecar file IDA produced into databases/ so binaries/
        # stays clean.
        moved_db: Path | None = None
        for suffix in IDA_SIDECAR_SUFFIXES:
            produced = binary.with_suffix(suffix)
            if not produced.exists():
                continue
            destination = DATABASES_DIR / produced.name
            shutil.move(str(produced), destination)
            if suffix == ".i64":
                moved_db = destination

        if moved_db is None:
            msg = f"ida-domain did not produce a .i64 for {binary.name}"
            raise RuntimeError(msg)
        print(f"  -> {moved_db.relative_to(ROOT)}")


def clean() -> None:
    for path in (BUILD_DIR, BINARIES_DIR, DATABASES_DIR):
        if path.exists():
            shutil.rmtree(path)
            print(f"  removed {path.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", action="store_true", help="Remove all build artefacts and exit.")
    parser.add_argument("--skip-database", action="store_true", help="Build binaries only; skip IDA analysis.")
    parser.add_argument("--skip-docker", action="store_true", help="Build native fixtures only; skip Docker fixtures.")
    parser.add_argument("--jobs", "-j", type=int, default=None, help="Parallel build job count.")
    args = parser.parse_args()

    if args.clean:
        clean()
        return

    configure_and_build(args.jobs)
    binaries = collect_binaries()
    if not args.skip_docker:
        binaries.extend(build_docker_fixtures())

    if args.skip_database:
        print("Skipping IDA database generation (--skip-database).")
        return

    generate_databases(binaries)
    print("Done.")


if __name__ == "__main__":
    main()
