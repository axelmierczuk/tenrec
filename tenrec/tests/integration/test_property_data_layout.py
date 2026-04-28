"""Property-based integration tests against the 'data_layout' fixture.

Verifies the patch/revert lifecycle for any byte value, and the byte-bytes
round-trip through ``set_value_at`` / ``get_value_at`` with a generated
hex pattern.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings

from tenrec.plugins.plugins.bytes import BytesPlugin

from ._helpers import attach, find_name_address
from ..strategies import byte_value


pytestmark = pytest.mark.fixture


_INTEGRATION_SETTINGS = settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


class TestPatchRevertProperty:
    @_INTEGRATION_SETTINGS
    @given(value=byte_value)
    def test_patch_then_revert_restores_original(self, data_layout_db, value):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        original = bytes_plugin.get_value_at(addr, "byte")
        bytes_plugin.patch_value_at(addr, value)
        try:
            assert bytes_plugin.get_value_at(addr, "byte") == value
            # The original-byte accessor must surface the pre-patch value
            # regardless of what we patched it to.
            assert bytes_plugin.get_original_value_at(addr, "byte") == original
        finally:
            bytes_plugin.revert_byte_at(addr)

        assert bytes_plugin.get_value_at(addr, "byte") == original


class TestSetValueRoundTripProperty:
    @_INTEGRATION_SETTINGS
    @given(value=byte_value)
    def test_set_byte_then_read_round_trips(self, data_layout_db, value):
        # set_value_at writes through to the database (no patch tracking),
        # so we don't need to restore — but we do need the fixture's
        # save_on_close=False to keep the on-disk file untouched.
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        assert bytes_plugin.set_value_at(addr, value, "byte") is True
        assert bytes_plugin.get_value_at(addr, "byte") == value
