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

    def test_get_reads_of_g_counter_includes_compute_sum(self, basic_db):
        # ``g_counter += result`` is read-modify-write, so compute_sum should
        # appear in both reads_of and writes_to.
        xrefs = attach(XrefsPlugin, basic_db)
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")
        counter_addr = find_name_address(basic_db, "_g_counter", "g_counter")

        reads = xrefs.get_reads_of(counter_addr)
        in_compute_sum = [
            r for r in reads if compute_sum.start_ea <= r.ea_t < compute_sum.end_ea
        ]
        assert in_compute_sum, (
            f"expected a reader of g_counter inside compute_sum; got reads at "
            f"{[str(r) for r in reads]}"
        )


# ---------------------------------------------------------------------------
# Xrefs plugin — call sites, jumps, and data-flag xrefs
# ---------------------------------------------------------------------------


class TestXrefsCallSitesAndJumpsAgainstBasic:
    def test_get_calls_to_compute_sum_lands_inside_main(self, basic_db):
        xrefs = attach(XrefsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")

        sites = xrefs.get_calls_to(HexEA(compute_sum.start_ea))

        assert sites, "expected at least one call site to compute_sum"
        in_main = [s for s in sites if main.start_ea <= s.ea_t < main.end_ea]
        assert in_main, (
            f"expected call to compute_sum from inside main [{hex(main.start_ea)}, "
            f"{hex(main.end_ea)}); got sites {[str(s) for s in sites]}"
        )

    def test_get_jumps_from_main_returns_addresses(self, basic_db):
        # main has an ``if`` branch, so IDA should record at least one jump
        # somewhere in its body. We don't pin the exact source — just walk
        # instructions until we find one with an outgoing jump.
        xrefs = attach(XrefsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")

        any_jumps = False
        for instr in basic_db.instructions.get_between(main.start_ea, main.end_ea):
            if xrefs.get_jumps_from(HexEA(instr.ea)):
                any_jumps = True
                break
        assert any_jumps, "expected a jump instruction somewhere in main"

    def test_get_xrefs_to_g_counter_with_data_flag(self, basic_db):
        from ida_domain.xrefs import XrefsFlags

        xrefs = attach(XrefsPlugin, basic_db)
        counter_addr = find_name_address(basic_db, "_g_counter", "g_counter")

        # DATA flag must surface read/write xrefs (compute_sum's load/store).
        # This exercises the flags parameter path through get_xrefs_to.
        data_xrefs = xrefs.get_xrefs_to(counter_addr, flags=XrefsFlags.DATA)
        assert data_xrefs, "expected DATA xrefs to g_counter"

    def test_get_xrefs_from_main_with_all_flag_returns_xrefs(self, basic_db):
        from ida_domain.xrefs import XrefsFlags

        xrefs = attach(XrefsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")

        # ``ALL`` flag means flow-edges + data + code xrefs. main's body must
        # contain instructions whose xrefs_from is non-empty under ALL.
        any_xrefs = False
        for instr in basic_db.instructions.get_between(main.start_ea, main.end_ea):
            if xrefs.get_xrefs_from(HexEA(instr.ea), flags=XrefsFlags.ALL):
                any_xrefs = True
                break
        assert any_xrefs, "expected at least one xref-from inside main with ALL flag"


# ---------------------------------------------------------------------------
# Functions plugin — write paths (set_name, rename_local_variable)
# ---------------------------------------------------------------------------


class TestFunctionsWriteAgainstBasic:
    def test_set_name_round_trips(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        new_name = "tenrec_compute_sum_renamed"

        with restore_name(basic_db, target.start_ea):
            assert functions.set_name(HexEA(target.start_ea), new_name) is True
            got = functions.get_at(HexEA(target.start_ea))
            assert got.name == new_name

    def test_rename_local_variable_round_trips(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        target = find_function(basic_db, "process_buffer", "_process_buffer")
        addr = HexEA(target.start_ea)

        # Local names are decompiler-assigned (a1, a2, v3, ...) and depend on
        # IDA's heuristics; pick whatever the first non-result local is named
        # rather than hardcoding.
        lvars = functions.get_local_variables(addr)
        original = next(
            (lv for lv in lvars if not lv.is_result and lv.name),
            None,
        )
        assert original is not None, f"expected at least one named local; got {lvars}"
        new_name = "tenrec_renamed_local"

        msg = functions.rename_local_variable(addr, original.name, new_name)
        assert "Renamed" in msg

        # Verify the rename surfaced via get_local_variables.
        renamed = {lv.name for lv in functions.get_local_variables(addr)}
        assert new_name in renamed, (
            f"expected {new_name} in locals after rename; got {sorted(renamed)}"
        )


# ---------------------------------------------------------------------------
# Names plugin — delete and force_name collision
# ---------------------------------------------------------------------------


class TestNamesDeleteAndForceAgainstBasic:
    def test_delete_removes_user_name(self, basic_db):
        names = attach(NamesPlugin, basic_db)
        addr = find_name_address(basic_db, "_g_counter", "g_counter")
        original = basic_db.names.get_at(addr.ea_t)

        # Set then delete; verifies the full lifecycle ends at "no user name".
        try:
            names.set_name(addr, "tenrec_about_to_delete")
            assert names.get_at(addr).name == "tenrec_about_to_delete"
            assert names.delete(addr) is True
            # IDA reverts to an auto-generated name (or no name at all) once
            # the user name is deleted. The contract: it's no longer the name
            # we set.
            current = basic_db.names.get_at(addr.ea_t)
            assert current != "tenrec_about_to_delete"
        finally:
            if original:
                basic_db.names.set_name(addr.ea_t, original)

    def test_force_name_auto_suffixes_on_collision(self, basic_db):
        names = attach(NamesPlugin, basic_db)
        first = find_name_address(basic_db, "_g_counter", "g_counter")
        second = find_name_address(basic_db, "_g_buffer", "g_buffer")
        shared_base = "tenrec_shared_name"

        with restore_name(basic_db, first.ea_t), restore_name(basic_db, second.ea_t):
            assert names.force_name(first, shared_base) is True
            # Second force_name with the same base must succeed and produce a
            # name that *starts* with the base (auto-suffixing can be _0, _1).
            assert names.force_name(second, shared_base) is True
            second_name = names.get_at(second).name
            assert second_name.startswith(shared_base), second_name
            assert second_name != shared_base, (
                "expected auto-suffix on collision, got identical name"
            )


# ---------------------------------------------------------------------------
# Segments plugin — set_name round-trip
# ---------------------------------------------------------------------------


class TestSegmentsSetNameAgainstBasic:
    def test_set_name_round_trips(self, basic_db):
        segments = attach(SegmentsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")
        original = segments.get_at(HexEA(main.start_ea)).name
        new_name = "tenrec_renamed_text"

        try:
            # ida-domain returns an int (1/0) rather than a bool, so check
            # truthiness rather than ``is True``.
            assert segments.set_name(HexEA(main.start_ea), new_name)
            assert segments.get_at(HexEA(main.start_ea)).name == new_name
        finally:
            # Restore the original segment name so we don't depend on
            # save_on_close=False alone for cleanup.
            segments.set_name(HexEA(main.start_ea), original)


# ---------------------------------------------------------------------------
# Comments plugin — variant kinds (REPEATABLE round-trip, POSTERIOR extra)
# ---------------------------------------------------------------------------


class TestCommentsVariantsAgainstBasic:
    def test_repeatable_comment_round_trip_via_plugin(self, basic_db):
        from ida_domain.comments import CommentKind

        comments = attach(CommentsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)
        marker = "tenrec_repeatable_marker"

        original = basic_db.comments.get_at(target.start_ea, CommentKind.REPEATABLE)
        try:
            assert comments.set(addr, marker, CommentKind.REPEATABLE) is True
            got = comments.get(addr, CommentKind.REPEATABLE)
            assert got.comment == marker
            # Plugin's delete with explicit kind must remove the same record.
            comments.delete(addr, CommentKind.REPEATABLE)
            with pytest.raises(Exception):
                comments.get(addr, CommentKind.REPEATABLE)
        finally:
            if original is not None:
                basic_db.comments.set_at(target.start_ea, original.comment, CommentKind.REPEATABLE)

    def test_posterior_extra_comment_round_trip(self, basic_db):
        from ida_domain.comments import ExtraCommentKind

        comments = attach(CommentsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)
        marker = "tenrec_posterior_marker"

        comments.set_extra(addr, 0, marker, ExtraCommentKind.POSTERIOR)
        try:
            assert comments.get_extra(addr, 0, ExtraCommentKind.POSTERIOR) == marker
            assert marker in comments.get_all_extra(addr, ExtraCommentKind.POSTERIOR)
        finally:
            comments.delete_extra(addr, 0, ExtraCommentKind.POSTERIOR)


# ---------------------------------------------------------------------------
# Entries plugin — write paths (add, rename, set_forwarder)
# ---------------------------------------------------------------------------


class TestEntriesWriteAgainstBasic:
    def test_add_new_entry_round_trips(self, basic_db):
        # Pick a free ordinal beyond the highest existing one to avoid the
        # collision case (which tests 'replace existing' rather than 'add').
        entries = attach(EntriesPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        existing = list(entries.get_ordinals())
        ordinal = max(existing, default=0) + 1
        new_name = "tenrec_extra_entry"

        assert entries.add(HexEA(target.start_ea), new_name, ordinal, make_code=False)
        assert entries.exists(ordinal) is True

        # The new entry must surface via every lookup path.
        by_name = entries.get_by_name(new_name)
        assert by_name.name == new_name
        by_ordinal = entries.get_by_ordinal(ordinal)
        assert by_ordinal.name == new_name

    def test_rename_changes_existing_entry(self, basic_db):
        entries = attach(EntriesPlugin, basic_db)
        existing = entries.get_all()
        assert existing, "expected at least one entry in basic fixture"
        target = existing[0]
        new_name = "tenrec_renamed_entry"

        try:
            assert entries.rename(target.ordinal, new_name)
            renamed = entries.get_by_ordinal(target.ordinal)
            assert renamed.name == new_name
        finally:
            entries.rename(target.ordinal, target.name)

    def test_set_forwarder_returns_bool_on_macho(self, basic_db):
        # DLL forwarding is a PE concept; on Mach-O it should fail cleanly
        # rather than crash. The plugin contract is "returns a bool" — that's
        # all we assert. We never depend on True here.
        entries = attach(EntriesPlugin, basic_db)
        existing = entries.get_all()
        assert existing
        target = existing[0]
        result = entries.set_forwarder(target.ordinal, "KERNEL32.CreateFileA")
        assert isinstance(result, bool | int)


# ---------------------------------------------------------------------------
# Functions plugin — lookup-side coverage (callees, lvar refs, data items, flags)
# ---------------------------------------------------------------------------


class TestFunctionsLookupExtraAgainstBasic:
    def test_get_callees_from_main_includes_compute_sum(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")

        callees = functions.get_callees(HexEA(main.start_ea))
        callee_starts = {c.start_ea.ea_t for c in callees}
        assert compute_sum.start_ea in callee_starts, (
            f"expected compute_sum in callees of main; got {sorted(callee_starts)}"
        )

    def test_get_local_variable_references_finds_uses(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        target = find_function(basic_db, "process_buffer", "_process_buffer")
        addr = HexEA(target.start_ea)

        lvars = functions.get_local_variables(addr)
        # Pick a non-result local that the body actually uses; loop body uses
        # min/max/sum/i in process_buffer. ``ea`` on a reference is optional
        # (some pseudocode-only references have no source EA), so we only
        # constrain references that *do* carry an EA.
        for lv in lvars:
            if lv.is_result or not lv.name:
                continue
            refs = functions.get_local_variable_references(addr, lv.name)
            if not refs:
                continue
            # Every reference with an EA must fall inside the function body.
            for ref in refs:
                if ref.ea is not None:
                    assert target.start_ea <= ref.ea.ea_t < target.end_ea
            # And the reference list must carry at least one access_type
            # string — that's the field always populated by ida-domain.
            assert all(r.access_type for r in refs)
            return
        pytest.fail("expected at least one local with references in process_buffer")

    def test_get_flags_surfaces_function_attributes(self, basic_db):
        # fatal_error is __attribute__((noreturn)); even if IDA's NORET
        # propagation is platform-dependent, get_flags must return a list of
        # strings without raising.
        functions = attach(FunctionsPlugin, basic_db)
        fatal = find_function(basic_db, "fatal_error", "_fatal_error")

        flags = functions.get_flags(HexEA(fatal.start_ea))
        assert isinstance(flags, list)
        assert all(isinstance(f, str) for f in flags)


# ---------------------------------------------------------------------------
# Names plugin — index lookup + demangle passthrough
# ---------------------------------------------------------------------------


class TestNamesLookupExtraAgainstBasic:
    def test_get_at_index_returns_a_known_name(self, basic_db):
        names = attach(NamesPlugin, basic_db)
        all_names = names.get_all()
        assert all_names, "expected at least one name in basic fixture"

        # The index should map back to a name from get_all (regardless of
        # ordering) — the contract is "any valid index resolves to a name
        # that's in the master list".
        first = names.get_at_index(0)
        assert first.name in {n.name for n in all_names}

    def test_get_count_matches_get_all_length(self, basic_db):
        names = attach(NamesPlugin, basic_db)
        # Same kind of cross-method consistency check that imports has.
        # Not all names are user-visible (some auto-generated names live in
        # the private list), so count >= len(get_all) rather than equality.
        assert names.get_count() >= len(names.get_all())

    def test_demangle_unmangled_name_passes_through(self, basic_db):
        names = attach(NamesPlugin, basic_db)
        # 'main' isn't C++-mangled; the demangler should return None or
        # the original name unchanged. What it MUST NOT do is raise.
        result = names.demangle_name("main")
        assert result in {None, "main"}


# ---------------------------------------------------------------------------
# Strings plugin — address / index / range lookups
# ---------------------------------------------------------------------------


class TestStringsLookupAgainstBasic:
    def test_get_at_index_returns_known_string(self, basic_db):
        strings = attach(StringsPlugin, basic_db)
        all_strings = strings.get_all()
        # Pin a string we know is in the fixture, then look it up by index.
        # The exact index isn't stable across IDA versions, so we hunt for it.
        for i in range(len(all_strings)):
            entry = strings.get_at_index(i)
            if entry.contents.decode(errors="replace") == "Hello, fixture":
                return
        pytest.fail("Hello, fixture not found via get_at_index")

    def test_get_at_address_resolves_known_literal(self, basic_db):
        strings = attach(StringsPlugin, basic_db)
        # Find the address by scanning get_all, then round-trip through
        # get_at_address. This validates the address-keyed lookup path.
        for entry in strings.get_all():
            if entry.contents.decode(errors="replace") == "Hello, fixture":
                got = strings.get_at_address(entry.address)
                assert got.contents == entry.contents
                return
        pytest.fail("Hello, fixture missing from strings.get_all")

    def test_get_between_returns_subset_of_get_all(self, basic_db):
        strings = attach(StringsPlugin, basic_db)
        all_strings = strings.get_all()
        if not all_strings:
            pytest.skip("no strings in fixture")
        # Use the address range covering all strings — the result should equal
        # the full set (every string lives somewhere inside that range).
        lo = min(s.address.ea_t for s in all_strings)
        hi = max(s.address.ea_t for s in all_strings) + 64
        between = strings.get_between(HexEA(lo), HexEA(hi))
        between_addrs = {s.address for s in between}
        # Subset relation: every result of get_between must be in get_all.
        for s in between:
            assert s in all_strings or any(a.address == s.address for a in all_strings)
        # And the wide range must include our pinned literal.
        assert any(
            s.contents.decode(errors="replace") == "Hello, fixture" for s in between
        ), f"expected Hello, fixture in {[s.contents for s in between]}"


# ---------------------------------------------------------------------------
# Xrefs plugin — get_jumps_to (paired with get_jumps_from)
# ---------------------------------------------------------------------------


class TestJumpsRoundTripAgainstBasic:
    def test_jumps_to_round_trips_against_jumps_from(self, basic_db):
        # main has an ``if (argc > 99)`` branch; somewhere in its body lives
        # an instruction with at least one outgoing jump. Capture its target
        # via get_jumps_from, then verify get_jumps_to(target) reports the
        # original source.
        xrefs = attach(XrefsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")

        for instr in basic_db.instructions.get_between(main.start_ea, main.end_ea):
            jumps = xrefs.get_jumps_from(HexEA(instr.ea))
            if not jumps:
                continue
            target = jumps[0]
            sources = xrefs.get_jumps_to(target)
            assert HexEA(instr.ea) in sources, (
                f"expected {hex(instr.ea)} in jumps_to({target}); got {[str(s) for s in sources]}"
            )
            return
        pytest.fail("no jump instructions found inside main")


# ---------------------------------------------------------------------------
# Xrefs plugin — get_xref_graph with direction=UP (caller graph)
# ---------------------------------------------------------------------------


class TestXrefGraphUpAgainstBasic:
    def test_graph_up_from_compute_sum_reaches_main(self, basic_db):
        from tenrec.plugins.plugins.xrefs import CGFlow

        xrefs = attach(XrefsPlugin, basic_db)
        main = find_function(basic_db, "main", "_main")
        compute_sum = find_function(basic_db, "compute_sum", "_compute_sum")

        graph = xrefs.get_xref_graph(
            HexEA(compute_sum.start_ea), depth=2, direction=CGFlow.UP
        )

        # The UP direction follows callers, so the graph rooted at
        # compute_sum must include main (its only caller).
        assert HexEA(compute_sum.start_ea) in graph
        assert HexEA(main.start_ea) in graph


# ---------------------------------------------------------------------------
# Comments plugin — delete REGULAR via plugin
# ---------------------------------------------------------------------------


class TestCommentsDeleteAgainstBasic:
    def test_set_then_delete_regular_via_plugin(self, basic_db):
        from tenrec.plugins.models.exceptions import OperationError

        comments = attach(CommentsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        addr = HexEA(target.start_ea)
        marker = "tenrec_delete_marker"

        with restore_comment(basic_db, target.start_ea):
            assert comments.set(addr, marker)
            assert comments.get(addr).comment == marker

            # delete returns a status string (current plugin contract); after
            # it runs, get must raise rather than return a stale comment.
            comments.delete(addr)
            with pytest.raises(OperationError, match="No comment"):
                comments.get(addr)


# ---------------------------------------------------------------------------
# Entries plugin — read-only paths not exercised elsewhere
# ---------------------------------------------------------------------------


class TestEntriesReadOnlyAgainstBasic:
    def test_get_addresses_matches_get_all(self, basic_db):
        entries = attach(EntriesPlugin, basic_db)
        addrs = entries.get_addresses()
        all_entries = entries.get_all()

        # get_addresses returns raw ea_t ints; EntryData.address is a HexEA
        # (str subclass). Normalise both via .ea_t / int() before comparing.
        addr_set = {int(a) for a in addrs}
        for e in all_entries:
            assert e.address.ea_t in addr_set, (
                f"{e.name}@{e.address} missing from get_addresses"
            )

    def test_get_start_resolves_to_main(self, basic_db):
        entries = attach(EntriesPlugin, basic_db)
        start = entries.get_start()
        # In the basic fixture, main IS the entry point.
        assert start.name in {"main", "_main"}

    def test_get_forwarders_returns_list_on_macho(self, basic_db):
        # Mach-O has no DLL forwarding; the contract is "returns a list".
        entries = attach(EntriesPlugin, basic_db)
        forwarders = entries.get_forwarders()
        assert isinstance(forwarders, list)


# ---------------------------------------------------------------------------
# Functions plugin — get_data_items
# ---------------------------------------------------------------------------


class TestFunctionsDataItemsAgainstBasic:
    def test_get_data_items_returns_list_for_simple_function(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")

        # compute_sum has no embedded jump tables or literal pools, so the
        # list is most likely empty — but the contract is "returns list of
        # HexEA" without raising.
        items = functions.get_data_items(HexEA(target.start_ea))
        assert isinstance(items, list)
        for item in items:
            # Every entry should be a HexEA wrapper.
            assert hasattr(item, "ea_t")


# ---------------------------------------------------------------------------
# Names plugin — get_demangled_name passthrough on unmangled C symbols
# ---------------------------------------------------------------------------


class TestNamesDemangledAtAgainstBasic:
    def test_get_demangled_name_passes_through_c_symbol(self, basic_db):
        from ida_domain.names import DemangleFlags
        from tenrec.plugins.models.exceptions import OperationError

        names = attach(NamesPlugin, basic_db)
        addr = find_name_address(basic_db, "_g_counter", "g_counter")

        # On C symbols there's nothing to demangle. IDA's demangler typically
        # returns either the original name or None — so the plugin either
        # returns NameData with the original string, or raises OperationError.
        try:
            got = names.get_demangled_name(addr, DemangleFlags(0))
        except OperationError:
            return  # acceptable contract for unmangled names
        assert got.name in {"g_counter", "_g_counter"}


# ---------------------------------------------------------------------------
# Bytes plugin — find_immediate_between, find_text_between
# (basic fixture has the literal 99 in main's argc check)
# ---------------------------------------------------------------------------


class TestFunctionsRangeAndCallersAgainstBasic:
    def test_get_between_includes_functions_in_range(self, basic_db):
        functions = attach(FunctionsPlugin, basic_db)
        all_funcs = functions.get_all()
        if len(all_funcs) < 2:
            pytest.skip("need at least two functions to exercise range query")

        starts = sorted(f.start_ea.ea_t for f in all_funcs)
        # Pick a window from the lowest function to one past the second-lowest
        # — guaranteed to contain at least one entry.
        result = functions.get_between(HexEA(starts[0]), HexEA(starts[1] + 1))
        result_starts = {f.start_ea.ea_t for f in result}
        assert starts[0] in result_starts

    def test_functions_get_callers_for_compute_sum(self, basic_db):
        # FunctionsPlugin has its own get_callers (FunctionData-shaped) that
        # parallels the XrefsPlugin call-site query (CallerData-shaped). They
        # share the underlying call-graph data but expose different shapes.
        functions = attach(FunctionsPlugin, basic_db)
        target = find_function(basic_db, "compute_sum", "_compute_sum")
        callers = functions.get_callers(HexEA(target.start_ea))
        names = {c.name for c in callers}
        assert {"main", "_main"} & names, (
            f"expected main in functions.get_callers; got {sorted(names)}"
        )


class TestEntriesAddressLookupsAgainstBasic:
    def test_get_at_resolves_main(self, basic_db):
        entries = attach(EntriesPlugin, basic_db)
        all_entries = entries.get_all()
        assert all_entries
        target = all_entries[0]

        looked_up = entries.get_at(target.address)
        assert looked_up.ordinal == target.ordinal
        assert looked_up.name == target.name

    def test_get_at_index_round_trips(self, basic_db):
        entries = attach(EntriesPlugin, basic_db)
        all_entries = entries.get_all()
        assert all_entries

        # Whichever entry IDA places at index 0 must match one of the entries
        # in get_all by ordinal — that's the cross-method consistency claim.
        first = entries.get_at_index(0)
        assert any(e.ordinal == first.ordinal for e in all_entries)


class TestBytesFindAgainstBasic:
    def test_find_immediate_locates_argc_check_constant(self, basic_db):
        from tenrec.plugins.models.exceptions import OperationError
        from tenrec.plugins.plugins.bytes import BytesPlugin

        # main has ``if (argc > 99)`` which the compiler translates to a
        # cmp/sub against 99 (0x63). The compiler may rewrite this to use a
        # different intermediate sequence on some platforms — if the
        # immediate isn't directly visible, OperationError is acceptable.
        bytes_plugin = attach(BytesPlugin, basic_db)
        try:
            hit = bytes_plugin.find_immediate_between(99)
        except OperationError:
            pytest.xfail("immediate 99 not directly in disassembly on this platform")
        assert hasattr(hit, "ea_t")

    def test_find_text_locates_known_string_reference(self, basic_db):
        from tenrec.plugins.models.exceptions import OperationError
        from tenrec.plugins.plugins.bytes import BytesPlugin

        # find_text_between scans both disassembly and comments. "FATAL"
        # appears in the format-string literal; whatever IDA's text-rendering
        # decides to surface, the call must either return a HexEA or raise
        # OperationError without crashing.
        bytes_plugin = attach(BytesPlugin, basic_db)
        try:
            hit = bytes_plugin.find_text_between("FATAL")
        except OperationError:
            pytest.xfail("FATAL not surfaced by find_text_between on this platform")
        assert hasattr(hit, "ea_t")
