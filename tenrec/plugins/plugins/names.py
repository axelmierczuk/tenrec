import re
from collections.abc import Callable, Iterator

from ida_domain.names import DemangleFlags, SetNameFlags

from tenrec.plugins.models import (
    HexEA,
    Instructions,
    NameData,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)


class NamesPlugin(PluginBase):
    """Plugin to manage symbol names, labels, and identifiers in the binary."""

    name = "names"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Manage symbol names, labels, and identifiers in the binary. Use for renaming functions, variables, "
            "and locations to improve code readability."
        ),
        interaction_style=[
            "Use meaningful, descriptive names",
            (
                "Use meaningful function names following conventions - snake_case for functions and variables, "
                "CamelCase for types and classes, g_ prefix for globals, s_ prefix for statics"
            ),
            (
                "If a name is not found, you likely need to set it first. For example, dword_ and loc_ names are "
                "auto-generated and need to be renamed based on their address"
            ),
        ],
        examples=[
            'Set the name of a symbol at an address: `names_set(0x401000, "process_input")`',
            'Find a symbol by name: `names_get_by_name("malloc")`',
            'Demangle a name: `names_demangle_name("_ZN4TestC1Ev")`',
        ],
        anti_examples=[
            "DON'T use reserved keywords as names",
            "DON'T create duplicate names",
            "DON'T use special characters that break naming rules",
        ],
    )

    @operation()
    def delete(self, ea: HexEA) -> bool:
        """Delete the name/label at the specified address.

        :param ea: Linear address where the name is located.
        :return: True if name was successfully deleted, False if no name existed or deletion failed.
        """
        return self.database.names.delete(ea.ea_t)

    @operation()
    def demangle_name(self, name: str, disable_mask: int | DemangleFlags = 0) -> str:
        """Demangle a C++ or other mangled symbol name to human-readable form.

        :param name: Mangled symbol name (e.g., "_ZN5MyApp4initEv").
        :param disable_mask: Flags to control demangling output (DemangleFlags enum or raw int).
        :return: Demangled name string or original name if demangling failed.
        """
        return self.database.names.demangle_name(name, disable_mask)

    @operation()
    def force_name(self, ea: HexEA, name: str, flags: int | SetNameFlags = SetNameFlags.NOCHECK) -> bool:
        """Force assignment of a name at address, auto-numbering if name already exists elsewhere.

        :param ea: Linear address to name.
        :param name: Desired name (will be suffixed with _1, _2, etc. if needed).
        :param flags: Name setting flags (SetNameFlags enum or raw int, default: NOCHECK).
        :return: True if name was successfully set (possibly with suffix), False otherwise.
        """
        return self.database.names.force_name(ea.ea_t, name, flags)

    @operation(options=[PaginatedParameter()])
    def get_all(self) -> list[NameData]:
        """Retrieves all named locations in the IDA Pro database.

        :return: List of NameData objects containing address and name pairs for all named locations.
        """
        return list(self.all_names())

    @operation(options=[PaginatedParameter()])
    def get_all_filtered(self, search: str) -> list[NameData]:
        """Search for named locations matching a regex pattern.

        :param search: Regular expression pattern to match against names.
        :return: List of NameData objects for names matching the pattern.
        """
        return list(self.all_names(callback_filter=lambda x: re.search(search, x.name) is not None))

    @operation()
    def get_at(self, ea: HexEA) -> NameData:
        """Get the name/label at a specific address. This is useful for checking dwork_, byte_, loc_, sub_ names.

        :param ea: The effective address to query.
        :return: NameData object containing the address and name.
        :raises OperationException: If no name exists at the given address.
        """
        name = self.database.names.get_at(ea.ea_t)
        if not name:
            msg = f"No name found at address: {ea}"
            raise OperationError(msg)
        return NameData.from_tuple((ea, name))

    @operation()
    def get_at_index(self, index: int) -> NameData:
        """Get a named element by its index in the names array.

        :param index: Zero-based index into the sorted names list.
        :return: NameData object containing address and name at the given index.
        :raises OperationException: If index is out of bounds.
        """
        name = self.database.names.get_at_index(index)
        if not name:
            msg = f"Failed to get name at index: {index}"
            raise OperationError(msg)
        return NameData.from_tuple(name)

    @operation()
    def get_count(self) -> int:
        """Get the total count of named locations in the database.

        :return: Integer count of all named addresses.
        """
        return self.database.names.get_count()

    @operation()
    def get_demangled_name(self, ea: HexEA, inhibitor: DemangleFlags, demangling_format_flags: int = 0) -> NameData:
        """Get the demangled version of a name at a specific address.

        :param ea: Linear address with a mangled name.
        :param inhibitor: Flags to control demangling output (DemangleFlags enum).
        :param demangling_format_flags: Additional demangling format flags.
        :return: NameData with demangled name if available.
        :raises OperationException: If no name exists at the address.
        """
        name = self.database.names.get_demangled_name(ea.ea_t, inhibitor, demangling_format_flags)
        if name is None:
            msg = f"No name found at address: {ea}"
            raise OperationError(msg)
        return NameData.from_tuple((ea, name))

    @operation()
    def set_name(self, ea: HexEA, name: str, flags: int | SetNameFlags = SetNameFlags.NOCHECK) -> bool:
        """Set or delete a name/label at the specified address.

         This is useful for renaming functions, variables, or locations such as dword_, byte_, loc_, sub_ names.

        :param ea: Linear address to name.
        :param name: New name to assign (empty string to delete existing name).
        :param flags: Name setting flags (SetNameFlags enum or raw int, default: NOCHECK).
        :return: True if name was successfully set or deleted, False if operation failed.
        """
        return self.database.names.set_name(ea.ea_t, name, flags)

    def all_names(self, callback_filter: Callable[[NameData], bool] | None = None) -> Iterator[NameData]:
        """Helper method to retrieve all names without pagination.

        :return: List of all NameData objects.
        """
        for addr, name in self.database.names.get_all():
            try:
                data = NameData.from_tuple((addr, name))
                if callback_filter and callback_filter(data):
                    yield data
                if not callback_filter:
                    yield data
            except OperationError:
                continue


plugin = NamesPlugin()
