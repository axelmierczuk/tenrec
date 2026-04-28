"""Integration tests against the 'data_layout' fixture binary.

Targets the bytes plugin: reading scalar values, checking type predicates,
locating bytes/text by content, and inspecting flags. Globals in the
fixture have hand-picked, predictable contents we can assert on.
"""

from __future__ import annotations

import pytest

from tenrec.plugins.models.ida import HexEA
from tenrec.plugins.plugins.bytes import BytesPlugin

from ._helpers import attach, find_name_address


pytestmark = pytest.mark.fixture


# Hand-laid constants in data_layout.c — keep these literals in sync with
# the C source. Mismatches here are exactly the bug class the suite catches.
G_DWORDS_0 = 0xCAFEBABE
G_DWORDS_1 = 0xDEADBEEF
G_QWORD = 0x1234567890ABCDEF
G_BYTES_PATTERN_HEX = "0102030405060708"
G_MARKER = "data_layout_marker"


# ---------------------------------------------------------------------------
# Scalar reads — every supported type
# ---------------------------------------------------------------------------


class TestScalarReadsAgainstDataLayout:
    def test_read_byte(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")
        assert bytes_plugin.get_value_at(addr, "byte") == 0x01

    def test_read_word(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_words", "g_words")
        assert bytes_plugin.get_value_at(addr, "word") == 0x1100

    def test_read_dword(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_dwords", "g_dwords")
        assert bytes_plugin.get_value_at(addr, "dword") == G_DWORDS_0

    def test_read_qword(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_qword", "g_qword")
        assert bytes_plugin.get_value_at(addr, "qword") == G_QWORD


# ---------------------------------------------------------------------------
# Predicates — is_data_at / is_code_at on known addresses
# ---------------------------------------------------------------------------


class TestPredicatesAgainstDataLayout:
    def test_globals_are_data_not_code(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        assert bytes_plugin.is_data_at(addr) is True
        assert bytes_plugin.is_code_at(addr) is False
        assert bytes_plugin.is_unknown_at(addr) is False
        assert bytes_plugin.is_head_at(addr) is True

    def test_function_address_is_code_not_data(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        # main is the only user code in data_layout.c.
        for addr_str, name in data_layout_db.names.get_all():
            if name in {"main", "_main"}:
                addr = HexEA(addr_str)
                assert bytes_plugin.is_code_at(addr) is True
                assert bytes_plugin.is_data_at(addr) is False
                return
        pytest.fail("Expected to find main / _main in name list")

    def test_get_data_size_reflects_applied_qword(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        # IDA's autoanalysis doesn't always classify wider integer globals as
        # a single item — for uint64_t it often leaves them as eight separate
        # bytes. The plugin contract is "size of the defined data item at
        # this address", so apply a qword definition first then verify it
        # round-trips. This is the realistic call sequence callers would use.
        qword_addr = find_name_address(data_layout_db, "_g_qword", "g_qword")
        assert bytes_plugin.create_data_at(qword_addr, "qword", count=1, force=True) is True
        assert bytes_plugin.get_data_size_at(qword_addr) == 8


# ---------------------------------------------------------------------------
# Searches — content-based lookups
# ---------------------------------------------------------------------------


class TestSearchesAgainstDataLayout:
    def test_find_bytes_locates_known_pattern(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        expected = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        hit = bytes_plugin.find_bytes_between(G_BYTES_PATTERN_HEX)
        assert hit == expected

    def test_find_marker_bytes_locates_string_content(self, data_layout_db):
        # find_text_between can match disassembly references rather than the
        # string content itself, which makes it ABI-dependent. Use a raw
        # byte search against the marker's hex encoding instead — that's a
        # content-only match and is guaranteed to land on the literal.
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        marker_hex = G_MARKER.encode("ascii").hex()

        hit = bytes_plugin.find_bytes_between(marker_hex)
        actual = bytes_plugin.get_bytes_at(hit, len(G_MARKER))
        assert bytes.fromhex(actual).decode("ascii") == G_MARKER


# ---------------------------------------------------------------------------
# Address navigation
# ---------------------------------------------------------------------------


class TestAddressNavigationAgainstDataLayout:
    def test_get_next_head_advances_past_qword(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        qword = find_name_address(data_layout_db, "_g_qword", "g_qword")

        nxt = bytes_plugin.get_next_head(qword)
        assert nxt.ea_t > qword.ea_t

    def test_get_previous_head_walks_backwards(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        dwords = find_name_address(data_layout_db, "_g_dwords", "g_dwords")

        prev = bytes_plugin.get_previous_head(dwords)
        assert prev.ea_t < dwords.ea_t


# ---------------------------------------------------------------------------
# Round-trip — read original bytes after a patch
# ---------------------------------------------------------------------------


class TestPatchRoundTripAgainstDataLayout:
    def test_patch_and_revert_byte(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        original = bytes_plugin.get_value_at(addr, "byte")
        bytes_plugin.patch_value_at(addr, 0xEE)
        try:
            assert bytes_plugin.get_value_at(addr, "byte") == 0xEE
            assert bytes_plugin.get_original_value_at(addr, "byte") == original
        finally:
            bytes_plugin.revert_byte_at(addr)
        assert bytes_plugin.get_value_at(addr, "byte") == original
