# Xrefs

Plugin to analyze cross-references between code and data.

## Purpose
Analyze cross-references between code and data. Use for understanding call graphs, data usage, and control flow relationships.

## Interaction Style
- This should be your go-to plugin for understanding relationships between code and data
- If ever unsure, use the reference graph with a depth of 1 to see immediate relationships
- Distinguish between code and data references
- Consider reference types (call, jump, read, write)

## Examples
- Get a call graph for function "main": `xrefs_get_reference_graph("main", depth=2, kind="code")`
- Find callers of a function at 0x401000: `xrefs_get_calls_to(0x401000)`
- Find data usage: `xrefs_get_data_xrefs_to(0x404000)`
- Add reference: `xrefs_add_code_xref(0x401000, 0x402000, 16)`

## Anti-Examples
- DON'T confuse code and data references
- DON'T ignore reference types
- DON'T create invalid cross-references




## Tools

### xrefs_get_xref_graph

```function
def xrefs_get_xref_graph(
    function_address: HexEA,
    depth: int = 3,
    flags: XrefsFlags = 4,
    direction: CGFlow = CGFlow.DOWN
) -> dict[tenrec.plugins.models.ida.HexEA, tenrec.plugins.plugins.xrefs.FunctionDataWithCallXrefs]:
```
Get the call graph for a function up to a certain depth.

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The address of the function to get the call graph for.
- **<span class='parameter'>depth</span>** (**<span class='return-type'>int</span>**): The depth to which to get the call graph.
- **<span class='parameter'>flags</span>** (**<span class='return-type'>XrefsFlags</span>**): The kind of xrefs to consider. Options are:
	 - `ALL`: *0*
	 - `NOFLOW`: *1*
	 - `DATA`: *2*
	 - `CODE`: *4*
	 - `CODE_NOFLOW`: *5*
- **<span class='parameter'>direction</span>** (**<span class='return-type'>CGFlow</span>**): Direction of the call graph. 'down' for functions called by the target function, 'up' for functions calling the target function.

**Returns:**
- **<span class='return-type'>dict[tenrec.plugins.models.ida.HexEA, tenrec.plugins.plugins.xrefs.FunctionDataWithCallXrefs]</span>**: A dictionary representing the call graph.


### xrefs_get_xrefs_from

```function
def xrefs_get_xrefs_from(
    address: HexEA,
    flags: XrefsFlags = 4,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.XrefData]:
```
Get all function calls made from a specific address.

**Args:**
- **<span class='parameter'>address</span>** (**<span class='return-type'>HexEA</span>**): Source address containing call instructions.
- **<span class='parameter'>flags</span>** (**<span class='return-type'>XrefsFlags</span>**): The kind of xrefs to consider. Options are:
	 - `ALL`: *0*
	 - `NOFLOW`: *1*
	 - `DATA`: *2*
	 - `CODE`: *4*
	 - `CODE_NOFLOW`: *5*
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.XrefData]</span>**: List of CallerData objects for each outgoing call.


### xrefs_get_xrefs_to

```function
def xrefs_get_xrefs_to(
    address: HexEA,
    flags: XrefsFlags = 4,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.XrefData]:
```
Get all locations that call a specific address.

**Args:**
- **<span class='parameter'>address</span>** (**<span class='return-type'>HexEA</span>**): Target address being called.
- **<span class='parameter'>flags</span>** (**<span class='return-type'>XrefsFlags</span>**): The kind of xrefs to consider. Options are:
	 - `ALL`: *0*
	 - `NOFLOW`: *1*
	 - `DATA`: *2*
	 - `CODE`: *4*
	 - `CODE_NOFLOW`: *5*
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.XrefData]</span>**: List of XrefData objects for each incoming call.
