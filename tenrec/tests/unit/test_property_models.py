"""Property-based tests for plain Python types (HexEA, pydantic models).

These tests live in the unit suite because they don't need a real IDA
database — they exercise pure transformation code where Hypothesis is
cheapest and yields the highest signal.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenrec.plugins.models.ida import (
    CommentData,
    EntryData,
    FunctionData,
    HexEA,
    NameData,
    StringData,
    XrefData,
)
from tenrec.tests.strategies import hex_ea_value


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# HexEA — numeric round-trip and string parsing
# ---------------------------------------------------------------------------


class TestHexEAProperty:
    @given(value=hex_ea_value)
    def test_int_round_trip(self, value):
        """HexEA(int) → ea_t must return the original int."""
        assert HexEA(value).ea_t == value

    @given(value=hex_ea_value)
    def test_int_format_is_lower_hex_with_prefix(self, value):
        """HexEA stringifies as lowercase ``0x...`` hex, no leading zeros."""
        h = HexEA(value)
        assert h.startswith("0x")
        assert h == f"0x{value:x}"

    @given(s=st.text(alphabet="0123456789abcdefABCDEF", min_size=1, max_size=12))
    def test_string_round_trip(self, s):
        """HexEA(<hex string>) parses back to int(s, 16)."""
        # The constructor accepts strings with or without a 0x prefix.
        assert HexEA(s).ea_t == int(s, 16)
        assert HexEA(f"0x{s}").ea_t == int(s, 16)

    @given(value=hex_ea_value)
    def test_two_constructor_forms_agree(self, value):
        """Building from int and from its hex string produce equal addresses."""
        assert HexEA(value) == HexEA(f"0x{value:x}")
        assert HexEA(value) == HexEA(f"{value:x}")

    @given(value=hex_ea_value)
    def test_pydantic_validation_accepts_int(self, value):
        """HexEA's pydantic schema validates ints — used when models are
        deserialised from JSON dicts."""
        # Use NameData which has a HexEA field.
        nd = NameData.model_validate({"address": value, "name": "x"})
        assert nd.address.ea_t == value


# ---------------------------------------------------------------------------
# Pydantic models — model_dump / model_validate must round-trip
# ---------------------------------------------------------------------------


class TestModelRoundTripProperty:
    @given(start=hex_ea_value, end=hex_ea_value, name=st.text(min_size=0, max_size=64))
    def test_function_data_round_trip(self, start, end, name):
        """FunctionData → dict → FunctionData preserves every field."""
        fd = FunctionData(start_ea=start, end_ea=end, name=name or "Unknown")
        restored = FunctionData.model_validate(fd.model_dump())
        assert restored == fd

    @given(
        ordinal=st.integers(min_value=0, max_value=2**32 - 1),
        addr=hex_ea_value,
        name=st.text(min_size=0, max_size=64),
        forwarder=st.one_of(st.none(), st.text(min_size=0, max_size=64)),
    )
    def test_entry_data_round_trip(self, ordinal, addr, name, forwarder):
        ed = EntryData(ordinal=ordinal, address=addr, name=name, forwarder_name=forwarder)
        assert EntryData.model_validate(ed.model_dump()) == ed

    @given(
        addr=hex_ea_value,
        length=st.integers(min_value=0, max_value=10000),
        type_str=st.text(min_size=0, max_size=32),
        contents=st.binary(min_size=0, max_size=200),
    )
    def test_string_data_round_trip(self, addr, length, type_str, contents):
        sd = StringData(address=addr, length=length, type=type_str, contents=contents)
        assert StringData.model_validate(sd.model_dump()) == sd

    @given(
        from_ea=hex_ea_value,
        to_ea=hex_ea_value,
        type_str=st.text(min_size=0, max_size=32),
        is_code=st.booleans(),
        user=st.booleans(),
        is_flow=st.booleans(),
    )
    def test_xref_data_round_trip(self, from_ea, to_ea, type_str, is_code, user, is_flow):
        xd = XrefData(
            from_ea=from_ea,
            to_ea=to_ea,
            type=type_str,
            is_code=is_code,
            user_defined=user,
            is_flow=is_flow,
        )
        assert XrefData.model_validate(xd.model_dump()) == xd

    @given(
        ea=hex_ea_value,
        comment=st.text(min_size=0, max_size=500),
        repeatable=st.booleans(),
    )
    def test_comment_data_round_trip(self, ea, comment, repeatable):
        cd = CommentData(ea=ea, comment=comment, repeatable=repeatable)
        assert CommentData.model_validate(cd.model_dump()) == cd


# ---------------------------------------------------------------------------
# Container invariants: HexEA hashing / equality consistency
# ---------------------------------------------------------------------------


class TestHexEAContainerInvariants:
    @given(value=hex_ea_value)
    def test_hash_eq_consistent(self, value):
        """Equal HexEAs must hash equal — required for use as dict keys."""
        a = HexEA(value)
        b = HexEA(f"0x{value:x}")
        assert a == b
        assert hash(a) == hash(b)

    @given(values=st.lists(hex_ea_value, min_size=1, max_size=10, unique=True))
    @settings(max_examples=50)
    def test_set_membership_round_trip(self, values):
        """A HexEA built from int N is found in a set seeded with HexEA(int N)."""
        seeded = {HexEA(v) for v in values}
        for v in values:
            assert HexEA(v) in seeded
            assert HexEA(f"0x{v:x}") in seeded
