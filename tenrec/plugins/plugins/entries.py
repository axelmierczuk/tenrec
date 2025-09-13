from ida_domain.strings import ea_t
from ida_kernwin import ida_ida

from tenrec.plugins.models import (
    EntryData,
    ForwarderInfo,
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)


class EntriesPlugin(PluginBase):
    """Plugin to manage program entry points, exports, and executable start addresses."""

    name = "entries"
    version = "1.0.0"

    instructions = Instructions(
        purpose="Manage program entry points, exports, and executable start addresses.",
        interaction_style=[
            "`entries_get_start` will provide you with the main entry point, and should be the first call you make unless otherwise specified",
            "Be cautious when creating or modifying entries, always very with the client if unsure",
            "Provide meaningful names for entry points",
        ],
        examples=[
            "Get main entry: `entries_get_start()`",
            'Find export: `entries_get_by_name("CreateFileW")`',
            'Add entry: `entries_add(0x401000, "custom_init", make_code=True)`',
            "List exports: `entries_get_all()`",
        ],
        anti_examples=[
            "DON'T assume entry point addresses without verification",
            "DON'T create duplicate entry points at the same address",
            "DON'T use invalid characters in entry point names",
        ],
    )

    @operation()
    def add(self, address: HexEA, name: str, ordinal: int | None = None, make_code: bool = True) -> bool:
        """Add a new program entry point (export/entrypoint).

        :param address: Linear address of the entry point.
        :param name: Name for the entry point.
        :param ordinal: Export ordinal number (None to auto-assign based on address).
        :param make_code: Convert bytes at address to code if True.
        :return: True if entry point was successfully added.
        """
        return self.database.entries.add(address.ea_t, name, ordinal, make_code)

    @operation()
    def exists(self, ordinal: int) -> bool:
        """Check if an entry point with specific ordinal exists.

        :param ordinal: Export ordinal number to check.
        :return: True if entry point with this ordinal exists, False otherwise.
        """
        return self.database.entries.exists(ordinal)

    @operation(options=[PaginatedParameter()])
    def get_addresses(self) -> list[ea_t]:
        """Get addresses of all program entry points.

        :return: List of effective addresses for all entry points.
        """
        return list(self.database.entries.get_addresses())

    @operation(options=[PaginatedParameter()])
    def get_all(self) -> list[EntryData]:
        """Retrieve all program entry points with full details.

        :return: List of EntryInfo objects containing ordinal, name, and function data.
        """
        result = []
        for entry in self.database.entries.get_all():
            try:
                result.append(EntryData.from_ida(entry))
            except OperationError:
                continue
        return result

    @operation()
    def get_at_index(self, index: int) -> EntryData:
        """Get entry point by its position in the entry table.

        :param index: Zero-based index (0 to get_count()-1).
        :return: EntryInfo object for the entry at this index.
        :raises OperationException: If index is out of bounds.
        """
        entry = self.database.entries.get_at_index(index)
        return EntryData.from_ida(entry)

    @operation()
    def get_at(self, address: HexEA) -> EntryData:
        """Find entry point at a specific address.

        :param address: Linear address of the entry point.
        :return: EntryInfo object for the entry at this address.
        :raises OperationException: If no entry point exists at address.
        """
        entry = self.database.entries.get_at(address.ea_t)
        return EntryData.from_ida(entry)

    @operation()
    def get_by_name(self, name: str) -> EntryData:
        """Find entry point by its export name.

        :param name: Exact name of the entry point.
        :return: EntryInfo object for the named entry.
        :raises OperationException: If no entry point with this name exists.
        """
        entry = self.database.entries.get_by_name(name)
        return EntryData.from_ida(entry)

    @operation()
    def get_by_ordinal(self, ordinal: int) -> EntryData:
        """Get entry point by its export ordinal.

        :param ordinal: Export ordinal number.
        :return: EntryInfo object for the entry with this ordinal.
        :raises OperationException: If no entry with this ordinal exists.
        """
        entry = self.database.entries.get_by_ordinal(ordinal)
        return EntryData.from_ida(entry)

    @operation()
    def get_count(self) -> int:
        """Count total program entry points.

        :return: Integer count of all defined entry points.
        """
        return self.database.entries.get_count()

    @operation(options=[PaginatedParameter()])
    def get_forwarders(self) -> list[ForwarderInfo]:
        """Get all forwarded exports (DLL export forwarding).

        :return: List of ForwarderInfo objects for entries that forward to other DLLs.
        """
        result = []
        for entry in self.database.entries.get_forwarders():
            result.append(ForwarderInfo(ordinal=entry.ordinal, name=entry.name))
        return result

    @operation()
    def get_start(self) -> EntryData:
        """Get the main program entry point (start address).

        :return: EntryInfo for the program's initial execution point.
        """
        start = ida_ida.inf_get_start_ea()
        return self.get_at(HexEA(start))

    @operation(options=[PaginatedParameter()])
    def get_ordinals(self) -> list[int]:
        """Get ordinal numbers of all entry points.

        :return: List of all export ordinal numbers.
        """
        return list(self.database.entries.get_ordinals())

    @operation()
    def rename(self, ordinal: int, new_name: str) -> bool:
        """Change the name of an entry point.

        :param ordinal: Ordinal number of entry to rename.
        :param new_name: New export name to assign.
        :return: True if rename succeeded, False otherwise.
        """
        return self.database.entries.rename(ordinal, new_name)

    @operation()
    def set_forwarder(self, ordinal: int, forwarder_name: str) -> bool:
        """Set DLL forwarding for an export.

        :param ordinal: Ordinal of entry to forward.
        :param forwarder_name: Target DLL and function (e.g., "KERNEL32.CreateFileA").
        :return: True if forwarder was set successfully.
        """
        return self.database.entries.set_forwarder(ordinal, forwarder_name)


plugin = EntriesPlugin()
