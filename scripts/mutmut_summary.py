#!/usr/bin/env python3
"""Print a useful summary of the latest ``mutmut run``.

Mutmut 2.5's ``mutmut results`` and ``mutmut html`` commands raise a
``QueryResultIterator`` error on Python 3.13 (pony-orm API drift).
This script reads the same SQLite cache directly and prints what the
broken command was supposed to: a count breakdown plus a list of
surviving mutants grouped by source file.

Usage:
    python scripts/mutmut_summary.py                # full report
    python scripts/mutmut_summary.py --show-diffs   # also dump the diff for each survivor
    python scripts/mutmut_summary.py --file comments.py  # filter by source file substring
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


CACHE_FILE = Path(".mutmut-cache")

# Status codes mutmut writes — see the mutmut.cache module.
SURVIVED = "bad_survived"
KILLED = "ok_killed"
TIMEOUT = "bad_timeout"
SUSPICIOUS = "ok_suspicious"
SKIPPED = "skipped"

STATUS_LABELS = {
    SURVIVED: "🙁 survived",
    KILLED: "🎉 killed",
    TIMEOUT: "⏰ timed out",
    SUSPICIOUS: "🤔 suspicious",
    SKIPPED: "🔇 skipped",
}


def load_summary(con: sqlite3.Connection, file_filter: str | None) -> dict[str, dict]:
    """Group counts and surviving mutant ids by source file."""
    cur = con.cursor()
    where = ""
    params: tuple = ()
    if file_filter:
        where = "WHERE sf.filename LIKE ?"
        params = (f"%{file_filter}%",)

    cur.execute(
        f"""
        SELECT sf.filename, m.status, m.id
        FROM Mutant m
        JOIN Line l ON m.line = l.id
        JOIN SourceFile sf ON l.sourcefile = sf.id
        {where}
        ORDER BY sf.filename, m.id
        """,
        params,
    )
    summary: dict[str, dict] = defaultdict(
        lambda: {"counts": defaultdict(int), "survivors": []}
    )
    for filename, status, mutant_id in cur.fetchall():
        bucket = summary[filename]
        bucket["counts"][status] += 1
        if status == SURVIVED:
            bucket["survivors"].append(mutant_id)
    return summary


def show_diff(mutant_id: int) -> None:
    """Render a mutmut show <id> diff inline."""
    if shutil.which("mutmut") is None:
        print(f"  (mutmut not on PATH — run `mutmut show {mutant_id}` manually)")
        return
    result = subprocess.run(
        ["mutmut", "show", str(mutant_id)],
        capture_output=True,
        text=True,
        check=False,
    )
    indented = "    " + result.stdout.replace("\n", "\n    ").rstrip()
    print(indented)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show-diffs", action="store_true", help="Print the diff for each surviving mutant.")
    parser.add_argument("--file", help="Only include source files whose path contains this substring.")
    args = parser.parse_args()

    if not CACHE_FILE.exists():
        print(f"No {CACHE_FILE} in {Path.cwd()} — run `mutmut run` first.", file=sys.stderr)
        return 1

    con = sqlite3.connect(CACHE_FILE)
    try:
        summary = load_summary(con, args.file)
    finally:
        con.close()

    if not summary:
        print("No mutants in cache (after applying filter).")
        return 0

    total_counts: dict[str, int] = defaultdict(int)
    print(f"{'file':<60} {'killed':>8} {'survived':>10} {'timeout':>8} {'other':>6}")
    print("-" * 96)
    for filename, bucket in sorted(summary.items()):
        counts = bucket["counts"]
        for status, n in counts.items():
            total_counts[status] += n
        other = counts.get(SUSPICIOUS, 0) + counts.get(SKIPPED, 0)
        print(
            f"{filename:<60} "
            f"{counts.get(KILLED, 0):>8} "
            f"{counts.get(SURVIVED, 0):>10} "
            f"{counts.get(TIMEOUT, 0):>8} "
            f"{other:>6}"
        )

    print("-" * 96)
    print(
        f"{'TOTAL':<60} "
        f"{total_counts.get(KILLED, 0):>8} "
        f"{total_counts.get(SURVIVED, 0):>10} "
        f"{total_counts.get(TIMEOUT, 0):>8} "
        f"{total_counts.get(SUSPICIOUS, 0) + total_counts.get(SKIPPED, 0):>6}"
    )
    total = sum(total_counts.values())
    if total:
        kill_rate = total_counts.get(KILLED, 0) / total
        print(f"\nKill rate: {kill_rate:.1%} ({total_counts.get(KILLED, 0)}/{total} mutants killed)")

    if args.show_diffs:
        print("\n" + "=" * 96)
        print("SURVIVING MUTANTS")
        print("=" * 96)
        for filename, bucket in sorted(summary.items()):
            if not bucket["survivors"]:
                continue
            print(f"\n{filename}:")
            for mutant_id in bucket["survivors"]:
                print(f"\n  --- mutant {mutant_id} ---")
                show_diff(mutant_id)

    return 0


if __name__ == "__main__":
    sys.exit(main())
