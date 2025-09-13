import contextlib

import ida_hexrays
import ida_typeinf as ti
from ida_hexrays import ida_typeinf
from idautils import ida_bytes, ida_name

from tenrec.plugins.models import (
    CustomModifier,
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)
from tenrec.plugins.plugins.utils import refresh_decompiler_ctext


class TypesPlugin(PluginBase):
    """Plugin to manage type information in the IDA database including structures, unions, enums, functions, and typedefs."""

    name = "types"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Manage type information in the IDA database including structures, unions, enums, functions, "
            "and typedefs. Use for declaring custom types and retrieving type metadata."
        ),
        interaction_style=[
            "Provide complete C declarations with proper syntax",
            "Use standard C type notation (struct, union, enum, typedef)",
            "Include semicolons in declarations",
        ],
        examples=[
            'Declare a struct: `types_declare_c_type("struct MyData { int id; char name[32]; };")`',
            'Declare typedef: `types_declare_c_type("typedef unsigned long DWORD;")`',
            "List all types: `types_list_local_types()` returns rich metadata for each type",
        ],
        anti_examples=[
            "DON'T declare incomplete or syntactically invalid types",
            "DON'T forget semicolons at the end of declarations",
            "DON'T declare conflicting type names without checking existing types",
        ],
    )

    @operation()
    def declare_c_type(self, c_declaration: str) -> str:
        """Declares a C declaration type.

        :param c_declaration: The C declaration
        :return:
        """
        til = ida_typeinf.get_idati()
        result = ida_typeinf.parse_decls(til, c_declaration, False, ida_typeinf.PT_SIL)
        if result != 0:
            msg = f"Failed to parse declaration: {c_declaration[:20]}..."
            raise OperationError(msg)
        return f"Declared type:\n{c_declaration[:20]}..."

    # TODO:Refactor: Break this into smaller helper methods
    @operation(options=[PaginatedParameter()])
    def list_local_types(self) -> list[dict]:
        """Enumerate local types (TIL/IDATI) with rich, structured metadata.

        Returns items shaped like:
            ```json
            {
                "ordinal": int,
                "name": str,
                "kind": str,  # "struct" | "union" | "enum" | "func" | "typedef" | "ptr" | "array" | "builtin" | "unknown"
                "size": int | None,  # size in bytes if known
                "decl_simple": str | None,  # 1-line C-ish declaration
                "decl_full": str
                | None,  # multi-line C declaration (with fields/args when available)
                "details": {
                    ...
                },  # kind-specific details (members, enum values, func args/ret, etc.)
            }
            ```
        :return: A list of dictionaries with type information.
        """

        # Print helpers (avoid crashing if IDA can't format something)
        def _print_decl(tif: ti.tinfo_t, flags: int) -> str | None:
            try:
                # _print() is the most reliable from Python; fall back to dstr() if needed.
                s = tif._print(None, flags)  # type: ignore[attr-defined]
                if s:
                    return str(s)
            except Exception:
                pass
            try:
                return tif.dstr()  # readable but not fully C-decl
            except Exception:
                return None

        C_DECL_FLAGS = (
            ti.PRTYPE_MULTI | ti.PRTYPE_TYPE | ti.PRTYPE_SEMI | ti.PRTYPE_DEF | ti.PRTYPE_METHODS | ti.PRTYPE_OFFSETS
        )
        SIMPLE_FLAGS = ti.PRTYPE_1LINE | ti.PRTYPE_TYPE | ti.PRTYPE_SEMI

        idati = ti.get_idati()
        limit = ti.get_ordinal_limit(idati)

        results: list[dict] = []

        for ordinal in range(1, limit):
            try:
                t = ti.tinfo_t()
                if not t.get_numbered_type(idati, ordinal):
                    continue

                # Prefer the stored name if any; fall back to anonymous marker
                name = t.get_type_name()
                if not name:
                    # get_numbered_type_name() sometimes yields better names for typedefs
                    try:
                        nn = ti.get_numbered_type_name(idati, ordinal)
                        if nn:
                            name = nn
                    except Exception:
                        pass
                if not name:
                    name = f"<anonymous #{ordinal}>"

                # classify
                if t.is_udt():
                    kind = "union" if t.is_union() else "struct"
                elif t.is_enum():
                    kind = "enum"
                elif t.is_func():
                    kind = "func"
                elif t.is_typedef():
                    kind = "typedef"
                elif t.is_ptr():
                    kind = "ptr"
                elif t.is_array():
                    kind = "array"
                elif t.is_decl_float() or t.is_decl_int() or t.is_decl_bool() or t.is_decl_char():
                    kind = "builtin"
                else:
                    kind = "unknown"

                # size (may be -1 for unsized/incomplete types)
                try:
                    sz = t.get_size()
                    size = None if sz < 0 else int(sz)
                except Exception:
                    size = None

                decl_simple = _print_decl(t, SIMPLE_FLAGS)
                decl_full = _print_decl(t, C_DECL_FLAGS)

                details: dict = {}

                # Struct/Union members
                if t.is_udt():
                    utd = ti.udt_type_data_t()
                    if t.get_udt_details(utd):
                        members = []
                        # Each entry is udt_member_t
                        for m in utd:
                            try:
                                m_t: ti.tinfo_t = m.type
                                members.append(
                                    {
                                        "name": m.name or "",
                                        "offset_bits": int(m.offset),  # bit offset
                                        "size_bytes": (None if m.size < 0 else int(m.size)),
                                        "is_bitfield": bool(m.is_bitfield()),
                                        "bit_size": (int(m.bs) if m.is_bitfield() else None),
                                        "decl": _print_decl(m_t, SIMPLE_FLAGS),
                                    }
                                )
                            except Exception:
                                continue
                        details["members"] = members
                        # layout hints
                        with contextlib.suppress(Exception):
                            details["packed"] = bool(utd.packed())

                # Enum values
                elif t.is_enum():
                    etd = ti.enum_type_data_t()
                    if t.get_enum_details(etd):
                        values = []
                        # iterate by index if supported, otherwise walk internal vector
                        try:
                            for i in range(etd.size()):
                                em = etd[i]  # enum_member_t
                                values.append({"name": em.name, "value": int(em.value), "is_bmask": bool(em.is_bf())})
                        except Exception:
                            # Fallback: try to access '.members' if exposed
                            try:
                                for em in etd.members:
                                    values.append(
                                        {
                                            "name": em.name,
                                            "value": int(em.value),
                                            "is_bmask": bool(em.is_bf()),
                                        }
                                    )
                            except Exception:
                                pass
                        details["values"] = values
                        with contextlib.suppress(Exception):
                            details["is_scoped"] = bool(etd.is_scoped())
                        with contextlib.suppress(Exception):
                            details["is_signed"] = bool(etd.is_signed())

                # Function prototype details
                elif t.is_func():
                    ftd = ti.func_type_data_t()
                    if t.get_func_details(ftd):
                        args = []
                        # func_type_data_t is indexable in Python
                        try:
                            for i in range(ftd.size()):
                                fa = ftd[i]  # funcarg_t
                                args.append(
                                    {
                                        "name": getattr(fa, "name", "") or f"arg{i}",
                                        "decl": _print_decl(fa.type, SIMPLE_FLAGS),
                                    }
                                )
                        except Exception:
                            # fallback if attributes differ
                            try:
                                for i, fa in enumerate(ftd):
                                    args.append(
                                        {
                                            "name": getattr(fa, "name", "") or f"arg{i}",
                                            "decl": _print_decl(fa.type, SIMPLE_FLAGS),
                                        }
                                    )
                            except Exception:
                                pass
                        # return type
                        try:
                            rett = ftd.rettype
                            ret_decl = _print_decl(rett, SIMPLE_FLAGS)
                        except Exception:
                            ret_decl = None
                        # calling convention (integer code; mapping left to caller)
                        try:
                            cc = int(ftd.cc)
                        except Exception:
                            cc = None
                        details.update(
                            {
                                "args": args,
                                "ret": ret_decl,
                                "cc": cc,
                                "is_vararg": bool(getattr(ftd, "is_vararg", lambda: False)()),
                            }
                        )

                # Pointer/array element type
                elif t.is_ptr() or t.is_array():
                    try:
                        elt = t.get_pointed_object() if t.is_ptr() else t.get_array_element()
                        details["element_decl"] = _print_decl(elt, SIMPLE_FLAGS)
                        if t.is_array():
                            with contextlib.suppress(Exception):
                                details["array_nelems"] = int(t.get_nitems())
                    except Exception:
                        pass

                results.append(
                    {
                        "ordinal": ordinal,
                        "name": name,
                        "kind": kind,
                        "size": size,
                        "decl_simple": decl_simple,
                        "decl_full": decl_full,
                        "details": details,
                    }
                )

            except Exception:
                # intentionally skip broken/partial entries and keep going
                continue

        return results

    @operation()
    def set_local_variable_type(self, function_address: HexEA, variable_name: str, new_type: str) -> str:
        """Set the local variable's type in a function.

        :param function_address: The function address
        :param variable_name: The name of the local variable
        :param new_type: The new type of the local variable
        :return:
        """
        func = self.database.functions.get_at(function_address.ea_t)
        if not func:
            msg = f"No function found at address: {function_address}"
            raise OperationError(msg)

        if not new_type.endswith(";"):
            new_type += ";"
        new_tif = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(new_tif, None, new_type, ida_typeinf.PT_SIL)
        result = ida_hexrays.rename_lvar(func.start_ea, variable_name, variable_name)
        if not result:
            msg = f"Failed to rename local variable: {variable_name}"
            raise OperationError(msg)
        modifier = CustomModifier(variable_name, new_tif)
        result = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
        if not result:
            msg = f"Failed to set type for local variable: {variable_name}"
            raise OperationError(msg)
        refresh_decompiler_ctext(func.start_ea)
        return f"Local variable {variable_name} type set to {new_type}"

    @operation()
    def set_function_prototype(self, function_address: HexEA, prototype: str) -> str:
        """Set a function prototype.

        :param function_address: The address of the function
        :param prototype: The prototype
        :return:
        """
        if not ida_bytes.is_loaded(function_address):
            msg = f"Address {function_address} is not in a loaded segment"
            raise OperationError(msg)
        func = self.database.functions.get_at(function_address.ea_t)
        tif = ida_typeinf.tinfo_t(prototype, None, ida_typeinf.PT_SIL)
        if not tif.is_func():
            msg = "Provided prototype is not a valid function type"
            raise OperationError(msg)
        if not ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL):
            msg = "Failed to apply function prototype"
            raise OperationError(msg)
        refresh_decompiler_ctext(func.start_ea)
        return f"Set prototype for function {func.name} at {HexEA(func.start_ea)}"

    @operation()
    def set_global_variable_type(self, variable_address: HexEA, new_type: str) -> str:
        """Set the global variable's type.

        :param variable_address: The address of the global variable
        :param new_type: The new type of the global variable
        :return:
        """
        if not ida_bytes.is_loaded(variable_address.ea_t):
            msg = f"Address {variable_address} is not in a loaded segment"
            raise OperationError(msg)

        new_type = new_type.strip()
        if not new_type.endswith(";"):
            new_type += ";"

        tif = ida_typeinf.tinfo_t()
        parse_flags = ida_typeinf.PT_SIL | ida_typeinf.PT_NDC
        result = ida_typeinf.parse_decl(tif, None, new_type, parse_flags)

        if result is None:
            msg = f"Failed to parse type declaration: '{new_type}'"
            raise OperationError(msg)

        if tif.empty():
            msg = f"Parsed type is empty or invalid: '{new_type}'"
            raise OperationError(msg)

        var_name = ida_name.get_name(variable_address) or f"var_{variable_address:X}"
        apply_flags = ida_typeinf.TINFO_DEFINITE | ida_typeinf.TINFO_DELAYFUNC

        if not ida_typeinf.apply_tinfo(variable_address, tif, apply_flags):
            msg = (
                f"Failed to apply type '{new_type}' to global variable '{var_name}' at {variable_address}. "
                f"This might be due to size conflicts or invalid type for this location."
            )
            raise OperationError(msg)
        return f"Successfully set type for global variable '{var_name}' at {variable_address} to '{new_type}'"


plugin = TypesPlugin()
