#!/usr/bin/env python3
"""Build C fixture binaries and generate IDA databases for integration tests.

Workflow:
    1. Configure + build the CMake project under ``build/``.
    2. Copy each produced binary into ``binaries/``.
    3. For every binary, open it with ida-domain (which auto-analyses and
       writes a ``.i64`` next to the binary), then move the resulting
       database into ``databases/``.

Usage:
    IDADIR=/path/to/ida python tenrec/tests/fixtures/build_fixtures.py
    python tenrec/tests/fixtures/build_fixtures.py --skip-database  # binaries only
    python tenrec/tests/fixtures/build_fixtures.py --clean

The script is idempotent: re-running rebuilds incrementally and replaces
existing databases.
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

# Companion files IDA produces alongside the .i64. These all need to move
# with the database, otherwise IDA will refuse to open it later.
IDA_SIDECAR_SUFFIXES = (".i64", ".id0", ".id1", ".id2", ".nam", ".til")


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
    parser.add_argument("--jobs", "-j", type=int, default=None, help="Parallel build job count.")
    args = parser.parse_args()

    if args.clean:
        clean()
        return

    configure_and_build(args.jobs)
    binaries = collect_binaries()

    if args.skip_database:
        print("Skipping IDA database generation (--skip-database).")
        return

    generate_databases(binaries)
    print("Done.")


if __name__ == "__main__":
    main()
