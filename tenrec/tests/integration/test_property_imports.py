"""Property tests for cross-method consistency in the imports plugin.

The plugin offers multiple paths to find the same import — by address,
by qualified name, by module — so the obvious invariant is "any import
returned by ``get_all()`` is also returned by every alternative lookup
that should reach it". Hypothesis runs the check against every import
the basic fixture exposes (rather than picking one by hand).
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tenrec.plugins.plugins.imports import ImportsPlugin

from ._helpers import attach


pytestmark = pytest.mark.fixture


_INTEGRATION_SETTINGS = settings(
    max_examples=15,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


def _imports_indexable(db):
    """Cache the import list once so Hypothesis can sample without
    re-querying the database for every example."""
    plugin = ImportsPlugin()
    plugin.database = db
    items = plugin.get_all()
    return plugin, items


class TestImportsCrossMethodConsistency:
    @_INTEGRATION_SETTINGS
    @given(idx=st.integers(min_value=0))
    def test_get_at_round_trips_for_any_import(self, basic_db, idx):
        plugin, imports = _imports_indexable(basic_db)
        if not imports:
            return  # nothing to assert against
        target = imports[idx % len(imports)]

        looked_up = plugin.get_at(target.address)

        assert looked_up.address == target.address
        assert looked_up.module_name == target.module_name
        assert looked_up.ordinal == target.ordinal

    @_INTEGRATION_SETTINGS
    @given(idx=st.integers(min_value=0))
    def test_get_by_name_round_trips_for_named_imports(self, basic_db, idx):
        plugin, imports = _imports_indexable(basic_db)
        named = [i for i in imports if i.name]
        if not named:
            return
        target = named[idx % len(named)]
        qualified = f"{target.module_name}!{target.name}"

        looked_up = plugin.get_by_name(qualified)

        assert looked_up.name == target.name
        assert looked_up.module_name == target.module_name
        assert looked_up.address == target.address

    def test_get_count_matches_get_all_length(self, basic_db):
        plugin, imports = _imports_indexable(basic_db)
        assert plugin.get_count() == len(imports)

    def test_get_module_count_matches_modules_length(self, basic_db):
        plugin = attach(ImportsPlugin, basic_db)
        assert plugin.get_module_count() == len(plugin.get_modules())

    @_INTEGRATION_SETTINGS
    @given(idx=st.integers(min_value=0))
    def test_get_for_module_consistent_with_get_all(self, basic_db, idx):
        """Imports filtered by module must equal imports of get_all() with
        matching module name."""
        plugin = attach(ImportsPlugin, basic_db)
        modules = plugin.get_modules()
        if not modules:
            return
        module = modules[idx % len(modules)]

        from_module = plugin.get_for_module(module.name)
        from_all = [i for i in plugin.get_all() if i.module_name == module.name]

        assert sorted(i.address for i in from_module) == sorted(i.address for i in from_all)
