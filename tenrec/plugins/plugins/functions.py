import re

import ida_hexrays

from tenrec.plugins.models import (
    FunctionData,
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)

from .utils import get_func_by_name, refresh_decompiler_ctext


class FunctionsPlugin(PluginBase):
    """Plugin to analyze and manage functions in the IDA Pro database."""

    name = "functions"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Analyze and manage functions in the binary including their boundaries, attributes, and relationships. "
            "Use for control flow analysis, function identification, and code structure understanding."
        ),
        interaction_style=[
            "Be extremely cautious when creating or modifying functions, always very with the client if unsure",
            (
                "Use meaningful function names following conventions - snake_case for functions and variables, "
                "CamelCase for types and classes, g_ prefix for globals, s_ prefix for statics"
            ),
            "Be aware of function boundaries and overlaps",
        ],
        examples=[
            "Get details on a function at 0x401000: `functions_get_at(0x401000)`",
            'Find by name: `functions_get_by_name("main")`',
            "Get pseudocode the pseudocode at function 0x401000: `functions_get_pseudocode(0x401000)`",
        ],
        anti_examples=[
            "DON'T create overlapping functions without checking boundaries",
            "DON'T assume function names are unique",
            "DON'T modify function boundaries without understanding call flow",
        ],
    )

    @operation(options=[PaginatedParameter()])
    def get_all(self) -> list[FunctionData]:
        """Retrieves all functions in the IDA Pro database.

        :return: List of all functions as FunctionData objects containing metadata like name, address, size, and attributes.
        """
        result = []
        for func in self.database.functions.get_all():
            result.append(FunctionData.from_func_t(func))
        return result

    @operation(options=[PaginatedParameter()])
    def get_all_filtered(self, search: str) -> list[FunctionData]:
        """Retrieves functions matching a regex pattern from the database.

        :param search: Regular expression pattern to match against function names.
        :return: List of functions whose names match the regex pattern as FunctionData objects.
        """
        result = []
        for func in self.database.functions.get_all():
            if func.name and re.search(search, func.name):
                result.append(FunctionData.from_func_t(func))
        return result

    @operation()
    def get_by_name(self, function_name: str) -> FunctionData:
        """Retrieves a function by its exact name.

        :param function_name: Exact name of the function to retrieve.
        :return: FunctionData object containing the function's metadata and properties.
        :raises OperationException: If no function with the given name exists.
        """
        resolved = get_func_by_name(self.database, function_name)
        return FunctionData.from_func_t(resolved)

    @operation()
    def get_at(self, function_address: HexEA) -> FunctionData:
        """Retrieves the function at the specified memory address.

        :param function_address: The effective address (EA) where the function is located.
        :return: FunctionData object containing the function at the specified address.
        :raises OperationException: If no function exists at the given address.
        """
        resolved = self.database.functions.get_at(function_address.ea_t)
        if not resolved:
            msg = f"No function found at address: {function_address}"
            raise OperationError(msg)
        return FunctionData.from_func_t(resolved)

    @operation(options=[PaginatedParameter()])
    def get_between(self, function_start_address: HexEA, function_end_address: HexEA) -> list[FunctionData]:
        """Retrieves all functions within the specified address range.

        :param function_start_address: Start address of the range (inclusive).
        :param function_end_address: End address of the range (exclusive).
        :return: List of functions whose start addresses fall within the range as FunctionData objects.
        :raises InvalidEAError: If start_ea or end_ea are not within database bounds.
        :raises InvalidParameterError: If start_ea >= end_ea.
        """
        result = []
        for func in self.database.functions.get_between(function_start_address.ea_t, function_end_address.ea_t):
            result.append(FunctionData.from_func_t(func))
        return result

    @operation(options=[PaginatedParameter()])
    def get_callees(self, function_address: HexEA) -> list[FunctionData]:
        """Retrieves all functions directly called by the function at the specified address (outgoing edges in call graph).

        :param function_address: The effective address of the calling function.
        :return: List of functions called by this function as FunctionData objects.
        :raises OperationException: If no function exists at the given address.
        """
        resolved = self.database.functions.get_at(function_address.ea_t)
        if not resolved:
            msg = f"No function found at address: {function_address}"
            raise OperationError(msg)
        result = []
        for func in self.database.functions.get_callees(resolved):
            result.append(FunctionData.from_func_t(func))
        return result

    @operation(options=[PaginatedParameter()])
    def get_callers(self, function_address: HexEA) -> list[FunctionData]:
        """Retrieves all functions that call the function at the specified address (incoming edges in call graph).

        :param function_address: The effective address of the target function.
        :return: List of functions that call this function as FunctionData objects.
        :raises OperationException: If no function exists at the given address.
        """
        resolved = self.database.functions.get_at(function_address.ea_t)
        if not resolved:
            msg = f"No function found at address: {function_address}"
            raise OperationError(msg)
        result = []
        for func in self.database.functions.get_callers(resolved):
            result.append(FunctionData.from_func_t(func))
        return result

    @operation()
    def get_pseudocode(self, function_address: HexEA, remove_tags: bool = True) -> str:
        """Retrieves the decompiled C-like pseudocode of the function at the specified address.

        :param function_address: The effective address of the function to decompile.
        :param remove_tags: Whether to remove IDA color/formatting tags for clean text output (default: True).
        :return: Decompiled pseudocode as a newline-separated string.
        :raises OperationException: If no function exists at the given address.
        """
        resolved = self.database.functions.get_at(function_address.ea_t)
        if not resolved:
            msg = f"No function found at address: {function_address}"
            raise OperationError(msg)
        return "\n".join(self.database.functions.get_pseudocode(resolved, remove_tags))

    @operation()
    def get_signature(self, function_address: HexEA) -> str:
        """Retrieves the function prototype/signature at the specified address.

        :param function_address: The effective address of the function.
        :return: Function signature string with return type and parameters (e.g., "int func(void *arg1, int arg2)").
        :raises OperationException: If no function exists at the given address.
        """
        resolved = self.database.functions.get_at(function_address.ea_t)
        if not resolved:
            msg = f"No function found at address: {function_address}"
            raise OperationError(msg)
        return self.database.functions.get_signature(resolved)

    @operation()
    def set_name(self, function_address: HexEA, name: str, auto_correct: bool = True) -> bool:
        """Sets the name of the function at the specified address.

        :param function_address: The effective address of the function to rename.
        :param name: The new name to assign to the function.
        :param auto_correct: Whether to automatically fix invalid characters in the name (default: True).
        :return: True if rename succeeded, False if failed.
        :raises OperationException: If no function exists at the given address.
        """
        resolved = self.database.functions.get_at(function_address.ea_t)
        if not resolved:
            msg = f"No function found at address: {function_address}"
            raise OperationError(msg)
        return self.database.functions.set_name(resolved, name, auto_correct)

    @operation()
    def rename_local_variable(self, function_address: HexEA, old_name: str, new_name: str) -> str:
        """Rename a local variable in a function.

        :param function_address: The address of the function
        :param old_name: The old name of the local variable
        :param new_name: The new name of the local variable
        :return:
        """
        func = self.database.functions.get_at(function_address.ea_t)
        if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
            msg = f"Failed to rename local variable: {old_name}"
            raise OperationError(msg)
        refresh_decompiler_ctext(func.start_ea)
        return f"Renamed variable {old_name} to {new_name}"


plugin = FunctionsPlugin()
