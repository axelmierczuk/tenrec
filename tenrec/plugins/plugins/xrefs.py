from enum import Enum

from ida_domain.xrefs import XrefsFlags

from tenrec.plugins.models import (
    FunctionData,
    HexEA,
    Instructions,
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
            "Find data usage: `xrefs_get_data_xrefs_to(0x404000)`",
            "Add reference: `xrefs_add_code_xref(0x401000, 0x402000, 16)`",
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
