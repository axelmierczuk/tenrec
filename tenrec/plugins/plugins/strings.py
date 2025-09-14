import re

from tenrec.plugins.models import (
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    StringData,
    operation,
)


class StringsPlugin(PluginBase):
    """Plugin for extracting and analyzing string literals in the binary."""

    name = "strings"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Extract and analyze string literals in the binary. Use for finding hardcoded values, messages, URLs, "
            "and other text data."
        ),
        interaction_style=[
            "Use regex patterns for filtering",
            "Look for strings to help you understand code functionality and identify interesting locations",
        ],
        examples=[
            "List all the strings: `strings_get_all()`",
            'Find URLs in strings: `strings_get_all_filtered("https?://")`',
        ],
        anti_examples=[
            "DON'T assume all text is valid strings",
            "DON'T ignore string encoding types",
            "DON'T overlook unicode strings",
        ],
    )

    @operation(options=[PaginatedParameter()])
    def get_all(self) -> list[StringData]:
        """Get all strings extracted from the binary.

        :return: List of StringInfo objects for all identified strings.
        """
        return list(map(StringData.from_ida, list(self.database.strings.get_all())))

    @operation(options=[PaginatedParameter()])
    def get_all_filtered(self, search: str) -> list[StringData]:
        """Search for strings matching a regex pattern.

        :param search: Regular expression pattern to match string content.
        :return: List of StringInfo objects for strings matching the pattern.
        """
        result = []
        for s in self.database.strings.get_all():
            if re.search(search, s.contents.decode()):
                result.append(StringData.from_ida(s))
        return result

    @operation()
    def get_at_address(self, address: HexEA) -> StringData:
        """Get detailed string information at a specific address.

        :param address: Address where the string is located.
        :return: StringInfo object with string content, type, and length.
        :raises OperationException: If no string exists at the address.
        """
        result = self.database.strings.get_at(address.ea_t)
        if not result:
            msg = f"No string found at address: {address}"
            raise OperationError(msg)
        return StringData.from_ida(result)

    @operation()
    def get_at_index(self, index: int) -> StringData:
        """Get string by its index in the string list.

        :param index: Zero-based index in the sorted string list.
        :return: StringInfo object for the string at this index.
        :raises OperationException: If index is out of bounds.
        """
        result = self.database.strings.get_at_index(index)
        if not result:
            msg = f"Failed to get string at index: {index}"
            raise OperationError(msg)
        return StringData.from_ida(result)

    @operation(options=[PaginatedParameter()])
    def get_between(self, start: HexEA, end: HexEA) -> list[StringData]:
        """Get all strings within an address range.

        :param start: Start address (inclusive).
        :param end: End address (exclusive).
        :return: List of StringInfo objects for strings in the range.
        :raises InvalidEAError: If addresses are outside database bounds.
        :raises InvalidParameterError: If start >= end.
        """
        return list(map(StringData.from_ida, list(self.database.strings.get_between(start.ea_t, end.ea_t))))


plugin = StringsPlugin()
