"""Helpers shared across integration tests.

Centralises the small operations every integration test needs — attaching a
plugin to a database, looking up a symbol that may have a leading underscore
on Mach-O, and snapshotting state we're about to mutate so tests don't
poison each other's view of the database.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import TypeVar

import pytest
from ida_domain import Database
from ida_domain.comments import CommentKind
from ida_funcs import func_t

from tenrec.plugins.models import HexEA, PluginBase


P = TypeVar("P", bound=PluginBase)


def attach(plugin_cls: type[P], db: Database) -> P:
    """Instantiate a plugin and bind it to ``db``."""
    plugin = plugin_cls()
    plugin.database = db
    return plugin


def find_function(db: Database, *candidate_names: str) -> func_t:
    """Look up a function by name, accepting platform-specific spellings.

    Mach-O builds prefix C symbols with an underscore (``_main`` instead of
    ``main``); pass every variant the test should accept.
    """
    candidates = set(candidate_names)
    for func in db.functions.get_all():
        if func.name in candidates:
            return func
    pytest.fail(f"None of {sorted(candidates)} found among fixture functions")


def find_name_address(db: Database, *candidate_names: str) -> HexEA:
    """Look up an address by symbol name (globals, statics, exported funcs)."""
    candidates = set(candidate_names)
    for addr, name in db.names.get_all():
        if name in candidates:
            return HexEA(addr)
    pytest.fail(f"None of {sorted(candidates)} found among database names")


@contextmanager
def restore_comment(db: Database, ea: int) -> Generator[None]:
    """Snapshot the regular comment at ``ea`` and restore it on exit.

    Use around any test that calls ``comments.set`` or ``comments.delete``
    so the database returns to its pre-test state even though the on-disk
    .i64 is opened with ``save_on_close=False``.
    """
    original = db.comments.get_at(ea, CommentKind.REGULAR)
    try:
        yield
    finally:
        if original is not None:
            db.comments.set_at(ea, original.comment, CommentKind.REGULAR)
        else:
            db.comments.delete_at(ea, CommentKind.REGULAR)


@contextmanager
def restore_name(db: Database, ea: int) -> Generator[None]:
    """Snapshot the name at ``ea`` and restore it on exit."""
    original = db.names.get_at(ea)
    try:
        yield
    finally:
        if original:
            db.names.set_name(ea, original)
        else:
            db.names.delete(ea)
