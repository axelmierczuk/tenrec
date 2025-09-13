from tenrec.plugins.models import (
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    SegmentData,
    operation,
)


class SegmentsPlugin(PluginBase):
    """Plugin to manage memory segments and sections in the binary."""

    name = "segments"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Manage memory segments and sections in the binary. Use for understanding memory layout, permissions, "
            "and program structure."
        ),
        interaction_style=[
            (
                "Use segments only when understanding memory layout is necessary. Most of the time, working through "
                "functions is sufficient."
            ),
        ],
        examples=[
            "List the segments: `segments_get_all()`",
            "Find a segment at a location: `segments_get_at(0x401000)`",
        ],
        anti_examples=[
            "DON'T assume segment layouts without checking",
            "DON'T modify segments without understanding implications",
            "DON'T ignore segment permissions",
        ],
    )

    @operation(options=[PaginatedParameter()])
    def get_all(self) -> list[SegmentData]:
        """Retrieves all memory segments in the IDA Pro database.

        :return: List of SegmentData objects containing segment information including name, start/end addresses, and permissions.
        """
        result = []
        for segment in self.database.segments.get_all():
            name = self.database.segments.get_name(segment)
            result.append(SegmentData.from_segment_t(segment, name))
        return result

    @operation()
    def get_at(self, ea: HexEA) -> SegmentData:
        """Retrieves the memory segment containing the specified address.

        :param ea: The effective address to locate within a segment.
        :return: SegmentData object for the segment containing the address.
        :raises OperationException: If no segment contains the given address.
        """
        segment = self.database.segments.get_at(ea.ea_t)
        if not segment:
            msg = f"No segment found at address: {ea}"
            raise OperationError(msg)
        name = self.database.segments.get_name(segment)
        return SegmentData.from_segment_t(segment, name)

    @operation()
    def set_name(self, ea: HexEA, name: str) -> bool:
        """Renames the segment containing the specified address.

        :param ea: Any effective address within the target segment.
        :param name: The new name to assign to the segment.
        :return: True if the rename operation succeeded, False if no segment found at address.
        """
        segment = self.database.segments.get_at(ea.ea_t)
        if not segment:
            return False
        return self.database.segments.set_name(segment, name)


plugin = SegmentsPlugin()
