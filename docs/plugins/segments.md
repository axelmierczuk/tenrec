# Segments

Plugin to manage memory segments and sections in the binary.

## Purpose
Manage memory segments and sections in the binary. Use for understanding memory layout, permissions, and program structure.

## Interaction Style
- Use segments only when understanding memory layout is necessary. Most of the time, working through functions is sufficient.

## Examples
- List the segments: `segments_get_all()`
- Find a segment at a location: `segments_get_at(0x401000)`

## Anti-Examples
- DON'T assume segment layouts without checking
- DON'T modify segments without understanding implications
- DON'T ignore segment permissions




## Tools

### segments_get_all

```function
def segments_get_all(
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.SegmentData]:
```
Retrieves all memory segments in the IDA Pro database.

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.SegmentData]</span>**: List of SegmentData objects containing segment information including name, start/end addresses, and permissions.


### segments_get_at

```function
def segments_get_at(ea: tenrec.plugins.models.ida.HexEA) -> SegmentData:
```
Retrieves the memory segment containing the specified address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to locate within a segment.

**Returns:**
- **<span class='return-type'>SegmentData</span>**: SegmentData object for the segment containing the address.


### segments_set_name

```function
def segments_set_name(ea: tenrec.plugins.models.ida.HexEA, name: str) -> bool:
```
Renames the segment containing the specified address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Any effective address within the target segment.
- **<span class='parameter'>name</span>** (**<span class='return-type'>str</span>**): The new name to assign to the segment.

**Returns:**
- **<span class='return-type'>bool</span>**: True if the rename operation succeeded, False if no segment found at address.
