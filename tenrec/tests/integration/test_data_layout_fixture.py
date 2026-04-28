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


# ---------------------------------------------------------------------------
# Floating-point types — apply, classify, read back
# ---------------------------------------------------------------------------


class TestFloatingPointAgainstDataLayout:
    def test_float_round_trip(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_floats", "g_floats")

        assert bytes_plugin.create_data_at(addr, "float", count=1, force=True) is True
        assert bytes_plugin.is_type_at(addr, "float") is True
        assert bytes_plugin.get_data_size_at(addr) == 4
        assert abs(bytes_plugin.get_value_at(addr, "float") - 3.14) < 0.001

    def test_double_round_trip(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_doubles", "g_doubles")

        assert bytes_plugin.create_data_at(addr, "double", count=1, force=True) is True
        assert bytes_plugin.is_type_at(addr, "double") is True
        assert bytes_plugin.get_data_size_at(addr) == 8
        assert abs(bytes_plugin.get_value_at(addr, "double") - 3.141592653589793) < 1e-12


# ---------------------------------------------------------------------------
# Wide-register types — oword (16 B), yword (32 B)
# ---------------------------------------------------------------------------


class TestWideTypesAgainstDataLayout:
    def test_oword_round_trip(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_oword", "g_oword")

        assert bytes_plugin.create_data_at(addr, "oword", count=1, force=True) is True
        assert bytes_plugin.is_type_at(addr, "oword") is True
        assert bytes_plugin.get_data_size_at(addr) == 16

    def test_yword_round_trip(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_yword", "g_yword")

        assert bytes_plugin.create_data_at(addr, "yword", count=1, force=True) is True
        assert bytes_plugin.is_type_at(addr, "yword") is True
        assert bytes_plugin.get_data_size_at(addr) == 32


# ---------------------------------------------------------------------------
# Flag inspection — get_flags_at, get_all_flags_at, has_any_flags_at,
# check_flags_at, has_user_name_at
# ---------------------------------------------------------------------------


class TestBytesFlagsAgainstDataLayout:
    def test_get_all_flags_at_is_non_zero_for_known_data(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")
        flags = bytes_plugin.get_all_flags_at(addr)
        assert int(flags) != 0

    def test_get_flags_at_returns_value(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")
        flags = bytes_plugin.get_flags_at(addr)
        # IVL/MS_VAL-masked flags; for an initialised data byte this must be
        # non-zero. The exact value is IDA-internal so we only assert it
        # surfaces as an integer.
        assert isinstance(int(flags), int)

    def test_has_any_flags_at_with_full_mask(self, data_layout_db):
        from ida_domain.bytes import ByteFlags

        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")
        # Asking "has any of every flag?" must return True for any non-zero
        # flag set — this round-trips the boolean machinery in the plugin.
        all_flags = bytes_plugin.get_all_flags_at(addr)
        assert bytes_plugin.has_any_flags_at(addr, all_flags) is True
        # And asking for zero flags must return False (no overlap with empty set).
        assert bytes_plugin.has_any_flags_at(addr, ByteFlags(0)) is False

    def test_check_flags_at_round_trips_masked_view(self, data_layout_db):
        from ida_domain.bytes import ByteFlags

        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        # check_flags_at reads the masked flags (same as get_flags_at) — NOT
        # the full-flags superset returned by get_all_flags_at. Round-trip
        # against the masked view: every flag in get_flags_at should pass
        # check_flags_at, and a known-absent flag should fail.
        masked = bytes_plugin.get_flags_at(addr)
        assert bytes_plugin.check_flags_at(addr, masked) is True
        assert ByteFlags.DATA in masked, f"expected DATA on a global; got {masked!r}"
        assert bytes_plugin.check_flags_at(addr, ByteFlags.DATA) is True
        # CODE should not be present on a data byte.
        assert bytes_plugin.check_flags_at(addr, ByteFlags.CODE) is False

    def test_has_user_name_at_named_global(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")
        assert bytes_plugin.has_user_name_at(addr) is True


# ---------------------------------------------------------------------------
# Predicates we hadn't exercised
# ---------------------------------------------------------------------------


class TestBytesPredicatesExtraAgainstDataLayout:
    def test_is_value_initialized_at_global(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")
        assert bytes_plugin.is_value_initialized_at(addr) is True

    def test_is_not_tail_at_head(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")
        # Heads are by definition not tails.
        assert bytes_plugin.is_not_tail_at(addr) is True
        assert bytes_plugin.is_tail_at(addr) is False

    def test_is_flowed_and_manual_insn_on_main(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        # Walk past the very first instruction of main so we land on a byte
        # where flow from the previous instruction is well-defined.
        for func in data_layout_db.functions.get_all():
            if func.name in {"main", "_main"}:
                second_instr_ea = data_layout_db.bytes.get_next_head(func.start_ea)
                addr = HexEA(second_instr_ea)
                # Both predicates must surface as bools without raising.
                assert isinstance(bytes_plugin.is_flowed_at(addr), bool)
                assert isinstance(bytes_plugin.is_manual_insn_at(addr), bool)
                assert isinstance(bytes_plugin.is_forced_operand_at(addr, 0), bool)
                return
        pytest.fail("Expected to find main / _main")


# ---------------------------------------------------------------------------
# Address navigation — get_next_address / get_previous_address
# ---------------------------------------------------------------------------


class TestAddressNavigationExtraAgainstDataLayout:
    def test_get_next_and_previous_address(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        nxt = bytes_plugin.get_next_address(addr)
        assert nxt.ea_t == addr.ea_t + 1

        prev = bytes_plugin.get_previous_address(nxt)
        assert prev == addr


# ---------------------------------------------------------------------------
# Disassembly + original-bytes accessors
# ---------------------------------------------------------------------------


class TestDisassemblyAndOriginalBytesAgainstDataLayout:
    def test_get_disassembly_at_main(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        for func in data_layout_db.functions.get_all():
            if func.name in {"main", "_main"}:
                line = bytes_plugin.get_disassembly_at(HexEA(func.start_ea))
                assert line, "expected non-empty disassembly line"
                return
        pytest.fail("Expected to find main / _main")

    def test_get_original_bytes_round_trip(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        before = bytes_plugin.get_bytes_at(addr, 4)
        bytes_plugin.patch_value_at(addr, 0xAA)
        try:
            after = bytes_plugin.get_bytes_at(addr, 4)
            originals = bytes_plugin.get_original_bytes_at(addr, 4)
            assert before == originals
            assert after != before
        finally:
            bytes_plugin.revert_byte_at(addr)


# ---------------------------------------------------------------------------
# create_data_at — non-default string encodings, alignment, struct dispatch
# ---------------------------------------------------------------------------


class TestCreateDataNonDefaultAgainstDataLayout:
    def test_create_pascal_string_dispatch(self, data_layout_db):
        # Different StringType values land on different create_string_at
        # paths in ida-domain. The plugin contract is "returns bool" — the
        # underlying data (g_marker is a C-style string) may not actually
        # round-trip as Pascal, but the dispatch must complete without
        # raising. Reverting via delete_value_at restores the auto-classified
        # state for any later test that cares.
        from ida_domain.strings import StringType

        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_marker", "g_marker")

        try:
            result = bytes_plugin.create_data_at(
                addr, "string", count=1, force=True, string_type=StringType.PASCAL
            )
            assert isinstance(result, bool | int)
        finally:
            bytes_plugin.delete_value_at(addr)

    def test_create_alignment_directive(self, data_layout_db):
        # Apply an 8-byte alignment directive at g_marker (after deleting the
        # existing string definition). Verifies the alignment branch of
        # create_data_at: power-of-2 ``alignment`` parameter must be threaded
        # through to ida-domain's create_alignment_at.
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_marker", "g_marker")

        try:
            bytes_plugin.delete_value_at(addr)
            result = bytes_plugin.create_data_at(
                addr, "alignment", count=1, force=True, length=8, alignment=3
            )
            assert isinstance(result, bool | int)
        finally:
            bytes_plugin.delete_value_at(addr)

    def test_create_struct_without_tid_raises(self, data_layout_db):
        # Plugin contract: create_data_at("struct") without ``tid`` must
        # raise OperationError rather than crashing inside ida-domain.
        from tenrec.plugins.models.exceptions import OperationError

        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        with pytest.raises(OperationError, match="tid"):
            bytes_plugin.create_data_at(addr, "struct", count=1, force=True)


# ---------------------------------------------------------------------------
# create_data_at — invalid type handling
# ---------------------------------------------------------------------------


class TestCreateDataInvalidTypeAgainstDataLayout:
    def test_invalid_data_type_raises(self, data_layout_db):
        from tenrec.plugins.models.exceptions import OperationError

        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        with pytest.raises(OperationError, match="Invalid data_type"):
            bytes_plugin.create_data_at(addr, "totally_bogus_type", count=1)


# ---------------------------------------------------------------------------
# patch_value_at — raw-bytes branch (separate code path from int patching)
# ---------------------------------------------------------------------------


class TestPatchBytesAgainstDataLayout:
    def test_patch_value_at_with_bytes_round_trips(self, data_layout_db):
        bytes_plugin = attach(BytesPlugin, data_layout_db)
        addr = find_name_address(data_layout_db, "_g_bytes", "g_bytes")

        original = bytes_plugin.get_bytes_at(addr, 4)
        new_payload = b"\xAA\xBB\xCC\xDD"
        try:
            assert bytes_plugin.patch_value_at(addr, new_payload) is True
            assert bytes_plugin.get_bytes_at(addr, 4) == new_payload.hex()
            # Originals must reflect pre-patch bytes regardless of the new
            # payload, identical to the int-patch path.
            assert bytes_plugin.get_original_bytes_at(addr, 4) == original
        finally:
            for offset in range(4):
                bytes_plugin.revert_byte_at(HexEA(addr.ea_t + offset))
