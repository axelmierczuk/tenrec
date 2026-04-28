"""Integration tests against the 'types_zoo' fixture binary.

Targets the types plugin: declaring C types, applying them to addresses,
listing local types, and resolving types by name. The fixture binary itself
just provides stable globals (``g_config``, ``g_word``) that we apply types
to — we don't depend on IDA extracting type info from DWARF.
"""

from __future__ import annotations

import pytest

from tenrec.plugins.models.ida import HexEA
from tenrec.plugins.plugins.types import TypesPlugin
from tenrec.plugins.plugins.xrefs import XrefsPlugin

from ._helpers import attach, find_function, find_name_address


pytestmark = pytest.mark.fixture


# ---------------------------------------------------------------------------
# Round-trip type declaration / application
# ---------------------------------------------------------------------------


class TestTypesRoundTrip:
    def test_declare_then_list_finds_new_type(self, types_zoo_db):
        types = attach(TypesPlugin, types_zoo_db)
        types.declare_c_type("struct tenrec_point_t { int x; int y; };")

        names = {t["name"] for t in types.list_local_types()}
        assert "tenrec_point_t" in names

    def test_list_local_types_filtered_matches_regex(self, types_zoo_db):
        types = attach(TypesPlugin, types_zoo_db)
        types.declare_c_type("struct tenrec_alpha_t { int a; };")
        types.declare_c_type("struct tenrec_beta_t { int b; };")

        result = types.list_local_types_filtered("^tenrec_")
        names = {t["name"] for t in result}
        assert {"tenrec_alpha_t", "tenrec_beta_t"} <= names

    def test_get_by_name_returns_full_body(self, types_zoo_db):
        types = attach(TypesPlugin, types_zoo_db)
        types.declare_c_type("struct tenrec_box_t { int w; int h; };")

        decl = types.get_by_name("tenrec_box_t")

        # get_by_name returns the *body* — fields must be visible. Different
        # IDA builds emit slightly different whitespace/keywords, so just
        # require the fields to round-trip rather than pinning exact text.
        assert "int w" in decl
        assert "int h" in decl

    def test_apply_at_then_get_at_round_trips(self, types_zoo_db):
        types = attach(TypesPlugin, types_zoo_db)
        types.declare_c_type("struct tenrec_config_t { int width; int height; int bg; };")

        # types_zoo declares g_config as a struct global; pick it up via
        # the symbol table to get a stable address.
        addr = find_name_address(types_zoo_db, "_g_config", "g_config")

        applied = types.apply_at(addr, "tenrec_config_t")
        assert applied is True

        # get_at returns the *reference* form, so the type name should appear.
        rendered = types.get_at(addr)
        assert "tenrec_config_t" in rendered

    def test_apply_declaration_at_in_one_step(self, types_zoo_db):
        types = attach(TypesPlugin, types_zoo_db)
        addr = find_name_address(types_zoo_db, "_g_word", "g_word")

        ok = types.apply_declaration_at(addr, "unsigned int")
        assert ok is True

        rendered = types.get_at(addr)
        # IDA usually prints these as "unsigned int" or "uint32_t".
        assert any(token in rendered for token in ("unsigned int", "uint32", "DWORD"))


# ---------------------------------------------------------------------------
# Error paths — make sure the plugin surfaces clean errors on bad input
# ---------------------------------------------------------------------------


class TestTypesErrorPaths:
    def test_get_by_name_raises_for_missing_type(self, types_zoo_db):
        from tenrec.plugins.models.exceptions import OperationError

        types = attach(TypesPlugin, types_zoo_db)
        with pytest.raises(OperationError, match="not found"):
            types.get_by_name("definitely_does_not_exist_t")

    def test_apply_at_raises_for_missing_type(self, types_zoo_db):
        from tenrec.plugins.models.exceptions import OperationError

        types = attach(TypesPlugin, types_zoo_db)
        addr = find_name_address(types_zoo_db, "_g_word", "g_word")
        with pytest.raises(OperationError, match="not found"):
            types.apply_at(addr, "definitely_does_not_exist_t")


# ---------------------------------------------------------------------------
# Indirect-call analysis — function pointer dispatch from apply_op
# ---------------------------------------------------------------------------


class TestIndirectCallsAgainstTypesZoo:
    def test_op_add_and_op_sub_have_callers(self, types_zoo_db):
        from ida_domain.xrefs import XrefsFlags

        xrefs = attach(XrefsPlugin, types_zoo_db)
        op_add = find_function(types_zoo_db, "op_add", "_op_add")
        op_sub = find_function(types_zoo_db, "op_sub", "_op_sub")

        # main reads function-pointer literals for these; IDA records that as
        # an xref-to even though the call goes through apply_op.
        assert xrefs.get_xrefs_to(HexEA(op_add.start_ea), flags=XrefsFlags.ALL)
        assert xrefs.get_xrefs_to(HexEA(op_sub.start_ea), flags=XrefsFlags.ALL)
