"""Property-based integration tests against the 'basic' fixture.

These exercise plugin contracts that should hold for any input meeting the
plugin's stated preconditions:

  - For any IDA-valid identifier ``n``, ``set_name(ea, n)`` then
    ``get_at(ea).name == n`` (modulo platform underscore prefixing IDA may
    apply, which we strip out before comparing).
  - For any non-empty text ``t`` (excluding control chars), setting it as
    a regular comment then reading it back yields the same string.

Each Hypothesis example reuses the same opened database (function-scoped
fixture) and undoes its mutation via the ``restore_*`` context managers,
so examples can't bleed into one another.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings

from tenrec.plugins.models.ida import HexEA
from tenrec.plugins.plugins.comments import CommentsPlugin
from tenrec.plugins.plugins.names import NamesPlugin

from ._helpers import attach, find_function, find_name_address, restore_comment, restore_name
from ..strategies import comment_text, valid_c_identifier


pytestmark = pytest.mark.fixture


# Hypothesis defaults (100 examples, strict deadline) are tuned for fast
# pure-Python tests. Each example here re-enters IDA, so cap at 25 and
# disable the per-example deadline. Also suppress the function-scoped-fixture
# health check — pytest fixtures share the open database across the whole
# @given test, which is what we want.
_INTEGRATION_SETTINGS = settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


class TestNamesRoundTripProperty:
    @_INTEGRATION_SETTINGS
    @given(name=valid_c_identifier(min_size=1, max_size=48))
    def test_set_then_get_round_trips(self, basic_db, name):
        names = attach(NamesPlugin, basic_db)
        addr = find_name_address(basic_db, "_g_counter", "g_counter")

        with restore_name(basic_db, addr.ea_t):
            assert names.set_name(addr, name) is True
            got = names.get_at(addr)
            # IDA may have rejected duplicate-name attempts silently — the
            # only invariant we assert is "what we wrote is what we read",
            # so compare directly.
            assert got.name == name


class TestCommentsRoundTripProperty:
    @_INTEGRATION_SETTINGS
    @given(text=comment_text)
    def test_set_then_get_regular_comment(self, basic_db, text):
        comments = attach(CommentsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)

        with restore_comment(basic_db, target.start_ea):
            assert comments.set(addr, text) is True
            got = comments.get(addr)
            assert got.comment == text
