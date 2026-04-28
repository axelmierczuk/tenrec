"""Property tests for ``*_get_all_filtered`` operations.

Every plugin that exposes a ``get_all_filtered(pattern)`` method must
satisfy: for any valid regex ``p``, ``filtered(p)`` is a subset of
``get_all()``. The trivial pattern ``".*"`` should match everything;
unmatched patterns should yield nothing.

Hypothesis lets us throw a wide variety of regexes at each plugin
without enumerating them by hand. Invalid regexes are dropped via
``assume()`` so the tests don't fail on patterns Python's ``re`` rejects.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from tenrec.plugins.plugins.comments import CommentsPlugin
from tenrec.plugins.plugins.functions import FunctionsPlugin
from tenrec.plugins.plugins.imports import ImportsPlugin
from tenrec.plugins.plugins.names import NamesPlugin
from tenrec.plugins.plugins.strings import StringsPlugin
from tenrec.plugins.plugins.types import TypesPlugin

from ._helpers import attach


pytestmark = pytest.mark.fixture


_INTEGRATION_SETTINGS = settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

# Mix of literal text and regex meta-characters. Hypothesis filters out
# patterns that fail to compile via assume().
_REGEX_ALPHABET = "abcdefghij_0123456789|.^$*+?()[]\\"
_pattern_strategy = st.text(alphabet=_REGEX_ALPHABET, min_size=0, max_size=12)


def _ensure_valid_pattern(pattern: str) -> None:
    """Drop patterns ``re`` can't compile rather than failing the test."""
    try:
        re.compile(pattern)
    except re.error:
        assume(False)


# ---------------------------------------------------------------------------
# Each plugin gets the same shape: filtered ⊆ all, plus the .* total-match
# and a never-matching probe.
# ---------------------------------------------------------------------------


class TestFunctionsFilterInvariant:
    @_INTEGRATION_SETTINGS
    @given(pattern=_pattern_strategy)
    def test_filtered_is_subset_of_all(self, basic_db, pattern):
        _ensure_valid_pattern(pattern)
        plugin = attach(FunctionsPlugin, basic_db)
        all_funcs = plugin.get_all()
        filtered = plugin.get_all_filtered(pattern)
        assert all(f in all_funcs for f in filtered)

    def test_dot_star_matches_all_named(self, basic_db):
        plugin = attach(FunctionsPlugin, basic_db)
        # get_all_filtered uses re.search against func.name; functions
        # without a name are filtered out, so the right baseline is
        # "all named".
        named = [f for f in plugin.get_all() if f.name]
        assert len(plugin.get_all_filtered(".*")) == len(named)


class TestNamesFilterInvariant:
    @_INTEGRATION_SETTINGS
    @given(pattern=_pattern_strategy)
    def test_filtered_is_subset_of_all(self, basic_db, pattern):
        _ensure_valid_pattern(pattern)
        plugin = attach(NamesPlugin, basic_db)
        all_names = plugin.get_all()
        filtered = plugin.get_all_filtered(pattern)
        assert all(n in all_names for n in filtered)

    def test_unmatchable_pattern_returns_empty(self, basic_db):
        plugin = attach(NamesPlugin, basic_db)
        assert plugin.get_all_filtered("zZqQXyz_no_such_name_anywhere_98765") == []


class TestCommentsFilterInvariant:
    @_INTEGRATION_SETTINGS
    @given(pattern=_pattern_strategy)
    def test_filtered_is_subset_of_all(self, basic_db, pattern):
        _ensure_valid_pattern(pattern)
        plugin = attach(CommentsPlugin, basic_db)
        all_comments = plugin.get_all()
        filtered = plugin.get_all_filtered(pattern)
        assert all(c in all_comments for c in filtered)


class TestStringsFilterInvariant:
    @_INTEGRATION_SETTINGS
    @given(pattern=_pattern_strategy)
    def test_filtered_is_subset_of_all(self, basic_db, pattern):
        _ensure_valid_pattern(pattern)
        plugin = attach(StringsPlugin, basic_db)
        all_strings = plugin.get_all()
        filtered = plugin.get_all_filtered(pattern)
        assert all(s in all_strings for s in filtered)


class TestImportsFilterInvariant:
    @_INTEGRATION_SETTINGS
    @given(pattern=_pattern_strategy)
    def test_filtered_is_subset_of_all(self, basic_db, pattern):
        _ensure_valid_pattern(pattern)
        plugin = attach(ImportsPlugin, basic_db)
        all_imports = plugin.get_all()
        filtered = plugin.get_all_filtered(pattern)
        assert all(i in all_imports for i in filtered)


class TestTypesFilterInvariant:
    @_INTEGRATION_SETTINGS
    @given(pattern=_pattern_strategy)
    def test_filtered_is_subset_of_all(self, types_zoo_db, pattern):
        _ensure_valid_pattern(pattern)
        plugin = attach(TypesPlugin, types_zoo_db)
        all_types = plugin.list_local_types()
        filtered = plugin.list_local_types_filtered(pattern)
        # Local types are dicts (not pydantic models), so equality works
        # field-by-field by default.
        assert all(t in all_types for t in filtered)
