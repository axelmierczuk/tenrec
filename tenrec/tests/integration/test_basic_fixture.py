"""Integration tests against the 'basic' fixture binary.

Exercises plugin code against a real ida-domain Database produced by
``tenrec/tests/fixtures/build_fixtures.py``. Catches the kind of API drift
that mock-based unit tests miss — for example, an ida-domain method
silently changing its return type would slip past mocks but fail here.

Before running:
    IDADIR=/path/to/ida python tenrec/tests/fixtures/build_fixtures.py
    IDADIR=/path/to/ida uv run pytest -m fixture
"""

from __future__ import annotations

import pytest

from tenrec.plugins.models.ida import HexEA
from tenrec.plugins.plugins.comments import CommentsPlugin
from tenrec.plugins.plugins.entries import EntriesPlugin
from tenrec.plugins.plugins.functions import FunctionsPlugin
from tenrec.plugins.plugins.imports import ImportsPlugin
from tenrec.plugins.plugins.names import NamesPlugin
from tenrec.plugins.plugins.segments import SegmentsPlugin
from tenrec.plugins.plugins.strings import StringsPlugin
from tenrec.plugins.plugins.xrefs import XrefsPlugin

from ._helpers import attach, find_function, find_name_address, restore_comment, restore_name


# Every test here needs the IDA-backed fixture; mark once at module level so
# we don't repeat the decorator on every function.
pytestmark = pytest.mark.fixture


# ---------------------------------------------------------------------------
# Functions plugin — pseudocode and locals (the surfaces that broke on 0.5.0)
# ---------------------------------------------------------------------------


class TestFunctionsAgainstBasic:
    def test_get_all_includes_fixture_symbols(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        names = {f.name for f in functions.get_all()}
        # Mach-O leading-underscore convention; check both forms.
        assert {"main", "_main"} & names
        assert {"compute_sum", "_compute_sum"} & names
        assert {"process_buffer", "_process_buffer"} & names

    def test_get_pseudocode_returns_real_decompilation(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")

        text = functions.get_pseudocode(HexEA(compute_sum.start_ea))

        # The decompiler is allowed to rename things, but the function shape
        # (an addition feeding a global) has to survive.
        assert text
        assert "+" in text or "add" in text.lower()

    def test_decompile_many_returns_per_function_text(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        targets = [
            find_function(basic_db, "compute_sum", "_compute_sum"),
            find_function(basic_db, "process_buffer", "_process_buffer"),
        ]
        result = functions.decompile_many([HexEA(t.start_ea) for t in targets])

        assert len(result) == 2
        for func in targets:
            assert HexEA(func.start_ea) in result
            assert result[HexEA(func.start_ea)].strip(), "expected non-empty pseudocode"

    def test_get_local_variables_for_process_buffer(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        target = find_function(basic_db, "process_buffer", "_process_buffer")

        lvars = functions.get_local_variables(HexEA(target.start_ea))

        # process_buffer takes (int *buf, int n) — at least two arguments visible.
        assert sum(1 for lv in lvars if lv.is_argument) >= 2

    def test_get_disassembly_returns_function_text(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")

        text = functions.get_disassembly(HexEA(compute_sum.start_ea))

        # Whatever instructions the compiler picked, there should be more than
        # one line and a return at the end somewhere.
        assert len(text.splitlines()) > 1
        assert "ret" in text.lower()

    def test_does_return_distinguishes_normal_and_noreturn(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")
        fatal = find_function(basic_db, "fatal_error", "_fatal_error")

        # compute_sum returns normally; this must always be true.
        assert functions.does_return(HexEA(compute_sum.start_ea)) is True

        # fatal_error is __attribute__((noreturn)). IDA picks this up on most
        # platforms but the propagation has historically been spotty for
        # statically-linked Mach-O. xfail loudly rather than asserting silently
        # so a future fix or regression is visible.
        if functions.does_return(HexEA(fatal.start_ea)) is not False:
            pytest.xfail("noreturn attribute not propagated by IDA on this platform")


# ---------------------------------------------------------------------------
# Xrefs plugin — call graph surfaces
# ---------------------------------------------------------------------------


class TestXrefsAgainstBasic:
    def test_get_callers_for_compute_sum(self, basic_db):
        xrefs = attach(XrefsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")

        callers = xrefs.get_callers(HexEA(target.start_ea))

        # main is the only caller in the fixture.
        assert callers
        assert any(
            (c.name in {"main", "_main"} or "main" in (c.name or "")) for c in callers
        ), f"expected main in callers, got {[c.name for c in callers]}"

    def test_get_calls_from_main_reaches_compute_sum(self, basic_db):
        xrefs = attach(XrefsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")

        # get_calls_from operates on a single instruction, so search across
        # the function body for a call to compute_sum.
        targets: set[HexEA] = set()
        for instr in basic_db.instructions.get_between(main.start_ea, main.end_ea):
            targets.update(xrefs.get_calls_from(HexEA(instr.ea)))

        assert HexEA(compute_sum.start_ea) in targets

    def test_xref_graph_reaches_called_functions(self, basic_db):
        xrefs = attach(XrefsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")
        process_buffer = find_function(basic_db, "process_buffer", "_process_buffer")

        graph = xrefs.get_xref_graph(HexEA(main.start_ea), depth=2)

        # main itself is the root, and both direct callees should be present.
        assert HexEA(main.start_ea) in graph
        assert HexEA(compute_sum.start_ea) in graph
        assert HexEA(process_buffer.start_ea) in graph


# ---------------------------------------------------------------------------
# Imports plugin
# ---------------------------------------------------------------------------


class TestImportsAgainstBasic:
    def test_get_all_returns_libc_symbols(self, basic_db):
        imports = attach(ImportsPlugin, basic_db)
        names = {i.name for i in imports.get_all() if i.name}
        # printf and exit are both invoked from the fixture.
        assert {"printf", "_printf"} & names
        assert {"exit", "_exit"} & names

    def test_get_modules_is_non_empty(self, basic_db):
        imports = attach(ImportsPlugin, basic_db)
        assert imports.get_modules(), "expected at least one imported module"

    def test_get_count_matches_get_all(self, basic_db):
        imports = attach(ImportsPlugin, basic_db)
        assert imports.get_count() == len(imports.get_all())


# ---------------------------------------------------------------------------
# Strings plugin — string literals from the fixture
# ---------------------------------------------------------------------------


class TestStringsAgainstBasic:
    def test_fixture_string_literals_are_extracted(self, basic_db):
        strings = attach(StringsPlugin, basic_db)
        all_strings = {s.contents.decode(errors="replace") for s in strings.get_all()}

        assert "Hello, fixture" in all_strings
        assert "FATAL: %s\n" in all_strings
        assert "too many args" in all_strings


# ---------------------------------------------------------------------------
# Names plugin — sanity check round-trip against real symbols
# ---------------------------------------------------------------------------


class TestNamesAgainstBasic:
    def test_is_valid_name_matches_idas_rules(self, basic_db):
        names = attach(NamesPlugin, basic_db)
        assert names.is_valid_name("my_function") is True
        # Leading digit is rejected by IDA's identifier rules.
        assert names.is_valid_name("1bad") is False


# ---------------------------------------------------------------------------
# Comments plugin — write/read round-trip on a real database
# ---------------------------------------------------------------------------


class TestCommentsAgainstBasic:
    def test_set_then_get_regular_comment(self, basic_db):
        comments = attach(CommentsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        marker = "tenrec_integration_test_marker"

        with restore_comment(basic_db, target.start_ea):
            comments.set(HexEA(target.start_ea), marker)
            got = comments.get(HexEA(target.start_ea))
            assert got.comment == marker

    def test_extra_anterior_comment_round_trip(self, basic_db):
        from ida_domain.comments import ExtraCommentKind

        comments = attach(CommentsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        marker = "tenrec_anterior_marker"
        addr = HexEA(target.start_ea)

        comments.set_extra(addr, 0, marker, ExtraCommentKind.ANTERIOR)
        try:
            assert comments.get_extra(addr, 0, ExtraCommentKind.ANTERIOR) == marker
            assert marker in comments.get_all_extra(addr, ExtraCommentKind.ANTERIOR)
        finally:
            comments.delete_extra(addr, 0, ExtraCommentKind.ANTERIOR)


# ---------------------------------------------------------------------------
# Entries plugin — program entry point and exported symbols
# ---------------------------------------------------------------------------


class TestEntriesAgainstBasic:
    def test_get_all_includes_main(self, basic_db):
        entries = attach(EntriesPlugin, basic_db)
        names = {e.name for e in entries.get_all()}
        assert {"main", "_main"} & names

    def test_get_by_name_resolves_main(self, basic_db):
        entries = attach(EntriesPlugin, basic_db)
        # IDA registers _main on Mach-O; try both spellings.
        try:
            entry = entries.get_by_name("_main")
        except Exception:
            entry = entries.get_by_name("main")
        assert entry.name in {"main", "_main"}

    def test_get_count_matches_get_all(self, basic_db):
        entries = attach(EntriesPlugin, basic_db)
        assert entries.get_count() == len(entries.get_all())


# ---------------------------------------------------------------------------
# Segments plugin — memory layout
# ---------------------------------------------------------------------------


class TestSegmentsAgainstBasic:
    def test_get_all_includes_code_segment(self, basic_db):
        segments = attach(SegmentsPlugin, basic_db)
        names = {s.name for s in segments.get_all()}
        # Mach-O code segment is __text; assertion is loose in case the
        # platform differs (ELF: .text, PE: .text).
        assert any(name in {"__text", ".text"} for name in names), f"got: {names}"

    def test_get_at_function_returns_code_segment(self, basic_db):
        segments = attach(SegmentsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")

        seg = segments.get_at(HexEA(main.start_ea))

        assert seg.name in {"__text", ".text"}

    def test_get_at_global_returns_data_segment(self, basic_db):
        segments = attach(SegmentsPlugin, basic_db)
        addr = find_name_address(basic_db, "_g_counter", "g_counter")

        seg = segments.get_at(addr)

        # Both __data and __common are valid for initialised globals on Mach-O.
        assert seg.name in {"__data", "__common", ".data", ".bss"}, f"got: {seg.name}"


# ---------------------------------------------------------------------------
# Names plugin — round-trip set / get / delete
# ---------------------------------------------------------------------------


class TestNamesRoundTripAgainstBasic:
    def test_rename_global_round_trips(self, basic_db):
        names = attach(NamesPlugin, basic_db)
        addr = find_name_address(basic_db, "_g_counter", "g_counter")
        new_name = "tenrec_renamed_counter"

        with restore_name(basic_db, addr.ea_t):
            assert names.set_name(addr, new_name) is True
            got = names.get_at(addr)
            assert got.name == new_name


# ---------------------------------------------------------------------------
# Xrefs plugin — data-flow against g_counter (compute_sum writes to it)
# ---------------------------------------------------------------------------


class TestDataFlowXrefsAgainstBasic:
    def test_get_writes_to_g_counter_includes_compute_sum(self, basic_db):
        xrefs = attach(XrefsPlugin, basic_db)
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")
        counter_addr = find_name_address(basic_db, "_g_counter", "g_counter")

        writes = xrefs.get_writes_to(counter_addr)

        # At least one writer should be inside compute_sum's body.
        assert writes
        in_compute_sum = [
            w for w in writes
            if compute_sum.start_ea <= w.ea_t < compute_sum.end_ea
        ]
        assert in_compute_sum, (
            f"expected a writer of g_counter inside compute_sum [{hex(compute_sum.start_ea)}, "
            f"{hex(compute_sum.end_ea)}); got writes at {[str(w) for w in writes]}"
        )
