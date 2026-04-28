from enum import Enum

from ida_domain.xrefs import XrefsFlags

from tenrec.plugins.models import (
    CallerData,
    FunctionData,
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    XrefData,
    operation,
)


class XrefWithData(XrefData):
    data: dict


class FunctionDataWithCallXrefs(FunctionData):
    xrefs: list[XrefWithData]


class CGFlow(Enum):
    UP = "up"
    DOWN = "down"


class XrefsPlugin(PluginBase):
    """Plugin to analyze cross-references between code and data."""

    name = "xrefs"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Analyze cross-references between code and data. Use for understanding call graphs, data usage, "
            "and control flow relationships."
        ),
        interaction_style=[
            "This should be your go-to plugin for understanding relationships between code and data",
            "If ever unsure, use the reference graph with a depth of 1 to see immediate relationships",
            "Distinguish between code and data references",
            "Consider reference types (call, jump, read, write)",
        ],
        examples=[
            'Get a call graph for function "main": `xrefs_get_reference_graph("main", depth=2, kind="code")`',
            "Find callers of a function at 0x401000: `xrefs_get_calls_to(0x401000)`",
            "Find detailed caller info with enclosing function: `xrefs_get_callers(0x401000)`",
            "Find addresses that read a global at 0x404000: `xrefs_get_reads_of(0x404000)`",
            "Find addresses that write a global at 0x404000: `xrefs_get_writes_to(0x404000)`",
        ],
        anti_examples=[
            "DON'T confuse code and data references",
            "DON'T ignore reference types",
            "DON'T create invalid cross-references",
        ],
    )

    @operation(options=[PaginatedParameter()])
    def get_xrefs_from(self, address: HexEA, flags: XrefsFlags = XrefsFlags.CODE) -> list[XrefData]:
        """Get all function calls made from a specific address.

        :param address: Source address containing call instructions.
        :param flags: The kind of xrefs to consider. Options are:
            `ALL`: *0*
            `NOFLOW`: *1*
            `DATA`: *2*
            `CODE`: *4*
            `CODE_NOFLOW`: *5*
        :return: List of CallerData objects for each outgoing call.
        """
        return list(map(XrefData.from_ida, list(self.database.xrefs.from_ea(address.ea_t, flags))))

    @operation(options=[PaginatedParameter()])
    def get_xrefs_to(self, address: HexEA, flags: XrefsFlags = XrefsFlags.CODE) -> list[XrefData]:
        """Get all locations that call a specific address.

        :param address: Target address being called.
        :param flags: The kind of xrefs to consider. Options are:
            `ALL`: *0*
            `NOFLOW`: *1*
            `DATA`: *2*
            `CODE`: *4*
            `CODE_NOFLOW`: *5*
        :return: List of XrefData objects for each incoming call.
        """
        return list(map(XrefData.from_ida, list(self.database.xrefs.to_ea(address.ea_t, flags))))

    @operation(options=[PaginatedParameter()])
    def get_calls_from(self, address: HexEA) -> list[HexEA]:
        """Get addresses of all functions called from the given address.

        Convenience filter that returns only call targets (not jumps or data refs).

        :param address: Source address containing call instructions.
        :return: List of called target addresses.
        """
        return [HexEA(ea) for ea in self.database.xrefs.calls_from_ea(address.ea_t)]

    @operation(options=[PaginatedParameter()])
    def get_calls_to(self, address: HexEA) -> list[HexEA]:
        """Get addresses where calls to the given address occur.

        Convenience filter that returns only call sites (not jumps or data refs).

        :param address: Target address being called.
        :return: List of source addresses containing call instructions.
        """
        return [HexEA(ea) for ea in self.database.xrefs.calls_to_ea(address.ea_t)]

    @operation(options=[PaginatedParameter()])
    def get_callers(self, function_address: HexEA) -> list[CallerData]:
        """Get detailed information for every caller of a function.

        Unlike `get_calls_to`, each result includes the caller's enclosing function and
        the xref type (call_near, call_far, etc.).

        :param function_address: Function start address.
        :return: List of CallerData objects describing each caller site.
        """
        return [CallerData.from_ida(c) for c in self.database.xrefs.get_callers(function_address.ea_t)]

    @operation(options=[PaginatedParameter()])
    def get_jumps_from(self, address: HexEA) -> list[HexEA]:
        """Get addresses jumped to from the given address.

        :param address: Source address containing jump instructions.
        :return: List of jump target addresses.
        """
        return [HexEA(ea) for ea in self.database.xrefs.jumps_from_ea(address.ea_t)]

    @operation(options=[PaginatedParameter()])
    def get_jumps_to(self, address: HexEA) -> list[HexEA]:
        """Get addresses where jumps to the given address occur.

        :param address: Target address.
        :return: List of source addresses containing jump instructions.
        """
        return [HexEA(ea) for ea in self.database.xrefs.jumps_to_ea(address.ea_t)]

    @operation(options=[PaginatedParameter()])
    def get_reads_of(self, data_address: HexEA) -> list[HexEA]:
        """Get addresses that read from the given data location.

        :param data_address: Data address.
        :return: List of source addresses that read the data.
        """
        return [HexEA(ea) for ea in self.database.xrefs.reads_of_ea(data_address.ea_t)]

    @operation(options=[PaginatedParameter()])
    def get_writes_to(self, data_address: HexEA) -> list[HexEA]:
        """Get addresses that write to the given data location.

        :param data_address: Data address.
        :return: List of source addresses that write to the data.
        """
        return [HexEA(ea) for ea in self.database.xrefs.writes_to_ea(data_address.ea_t)]

    @operation()
    def get_xref_graph(
        self,
        function_address: HexEA,
        depth: int = 3,
        flags: XrefsFlags = XrefsFlags.CODE,
        direction: CGFlow = CGFlow.DOWN,
    ) -> dict[HexEA, FunctionDataWithCallXrefs]:
        """Get the call graph for a function up to a certain depth.

        :param function_address: The address of the function to get the call graph for.
        :param depth: The depth to which to get the call graph.
        :param flags: The kind of xrefs to consider. Options are:
            `ALL`: *0*
            `NOFLOW`: *1*
            `DATA`: *2*
            `CODE`: *4*
            `CODE_NOFLOW`: *5*
        :param direction: Direction of the call graph. 'down' for functions called by the target function, 'up' for functions calling the target function.
        :return: A dictionary representing the call graph.
        """
        func = self.database.functions.get_at(function_address.ea_t)
        if func is None:
            msg = f"No function found at address: {function_address}"
            raise OperationError(msg)

        func = FunctionData.from_func_t(func)
        return self.call_graph_helper(
            func, graph={}, current_depth=0, max_depth=depth, direction=direction, flags=flags
        )

    def call_graph_helper(
        self,
        function: FunctionData,
        graph: dict[HexEA, FunctionDataWithCallXrefs],
        current_depth: int = 0,
        max_depth: int = 3,
        direction: CGFlow = CGFlow.DOWN,
        flags: XrefsFlags = XrefsFlags.CODE,
    ) -> dict[HexEA, FunctionDataWithCallXrefs]:
        if current_depth >= max_depth:
            return graph

        if function.start_ea in graph:
            return graph

        xref_function = FunctionDataWithCallXrefs(**function.model_dump(), xrefs=[])
        graph[function.start_ea] = xref_function

        instructions = self.database.instructions.get_between(function.start_ea.ea_t, function.end_ea.ea_t)

        found_calls = {}

        for instruction in instructions:
            if direction == CGFlow.DOWN:
                references = self.database.xrefs.from_ea(instruction.ea, flags=flags)
            elif direction == CGFlow.UP:
                references = self.database.xrefs.to_ea(instruction.ea, flags=flags)
            else:
                msg = "Invalid direction value"
                raise ValueError(msg)

            for ref in references:
                xref = XrefData.from_ida(ref)
                if found_calls.get(xref.to_ea, False):
                    continue

                if direction == CGFlow.DOWN:
                    func_ref = xref.to_ea.ea_t
                elif direction == CGFlow.UP:
                    func_ref = xref.from_ea.ea_t
                else:
                    msg = "Invalid direction value"
                    raise ValueError(msg)

                callee_func = self.database.functions.get_at(func_ref)
                if not callee_func:
                    continue
                callee_func_data = FunctionData.from_func_t(callee_func)

                if not callee_func:
                    xref = XrefWithData(**xref.model_dump(), data={"error": "No function found at the call location"})
                else:
                    xref = XrefWithData(**xref.model_dump(), data=callee_func_data.model_dump())

                graph[function.start_ea].xrefs.append(xref)

                found_calls[xref.to_ea.ea_t] = True
                self.call_graph_helper(callee_func_data, graph, current_depth + 1, max_depth)
        return graph


plugin = XrefsPlugin()
