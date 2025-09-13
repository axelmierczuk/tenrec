# Entries

Plugin to manage program entry points, exports, and executable start addresses.

## Purpose
Manage program entry points, exports, and executable start addresses.

## Interaction Style
- `entries_get_start` will provide you with the main entry point, and should be the first call you make unless otherwise specified
- Be cautious when creating or modifying entries, always very with the client if unsure
- Provide meaningful names for entry points

## Examples
- Get main entry: `entries_get_start()`
- Find export: `entries_get_by_name("CreateFileW")`
- Add entry: `entries_add(0x401000, "custom_init", make_code=True)`
- List exports: `entries_get_all()`

## Anti-Examples
- DON'T assume entry point addresses without verification
- DON'T create duplicate entry points at the same address
- DON'T use invalid characters in entry point names




## Tools

### entries_add

```function
def entries_add(
    address: HexEA,
    name: str,
    ordinal: int | None = None,
    make_code: bool = True
) -> bool:
```
Add a new program entry point (export/entrypoint).

**Args:**
- **<span class='parameter'>address</span>** (**<span class='return-type'>HexEA</span>**): Linear address of the entry point.
- **<span class='parameter'>name</span>** (**<span class='return-type'>str</span>**): Name for the entry point.
- **<span class='parameter'>ordinal</span>** (**<span class='return-type'>int | None</span>**): Export ordinal number (None to auto-assign based on address).
- **<span class='parameter'>make_code</span>** (**<span class='return-type'>bool</span>**): Convert bytes at address to code if True.

**Returns:**
- **<span class='return-type'>bool</span>**: True if entry point was successfully added.


### entries_exists

```function
def entries_exists(ordinal: int) -> bool:
```
Check if an entry point with specific ordinal exists.

**Args:**
- **<span class='parameter'>ordinal</span>** (**<span class='return-type'>int</span>**): Export ordinal number to check.

**Returns:**
- **<span class='return-type'>bool</span>**: True if entry point with this ordinal exists, False otherwise.


### entries_get_addresses

```function
def entries_get_addresses(offset: int = 0, limit: int = 100) -> list[int]:
```
Get addresses of all program entry points.

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[int]</span>**: List of effective addresses for all entry points.


### entries_get_all

```function
def entries_get_all(
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.EntryData]:
```
Retrieve all program entry points with full details.

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.EntryData]</span>**: List of EntryInfo objects containing ordinal, name, and function data.


### entries_get_at

```function
def entries_get_at(address: tenrec.plugins.models.ida.HexEA) -> EntryData:
```
Find entry point at a specific address.

**Args:**
- **<span class='parameter'>address</span>** (**<span class='return-type'>HexEA</span>**): Linear address of the entry point.

**Returns:**
- **<span class='return-type'>EntryData</span>**: EntryInfo object for the entry at this address.


### entries_get_at_index

```function
def entries_get_at_index(index: int) -> EntryData:
```
Get entry point by its position in the entry table.

**Args:**
- **<span class='parameter'>index</span>** (**<span class='return-type'>int</span>**): Zero-based index (0 to get_count()-1).

**Returns:**
- **<span class='return-type'>EntryData</span>**: EntryInfo object for the entry at this index.


### entries_get_by_name

```function
def entries_get_by_name(name: str) -> EntryData:
```
Find entry point by its export name.

**Args:**
- **<span class='parameter'>name</span>** (**<span class='return-type'>str</span>**): Exact name of the entry point.

**Returns:**
- **<span class='return-type'>EntryData</span>**: EntryInfo object for the named entry.


### entries_get_by_ordinal

```function
def entries_get_by_ordinal(ordinal: int) -> EntryData:
```
Get entry point by its export ordinal.

**Args:**
- **<span class='parameter'>ordinal</span>** (**<span class='return-type'>int</span>**): Export ordinal number.

**Returns:**
- **<span class='return-type'>EntryData</span>**: EntryInfo object for the entry with this ordinal.


### entries_get_count

```function
def entries_get_count() -> int:
```
Count total program entry points.

**Returns:**
- **<span class='return-type'>int</span>**: Integer count of all defined entry points.


### entries_get_forwarders

```function
def entries_get_forwarders(
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.ForwarderInfo]:
```
Get all forwarded exports (DLL export forwarding).

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.ForwarderInfo]</span>**: List of ForwarderInfo objects for entries that forward to other DLLs.


### entries_get_ordinals

```function
def entries_get_ordinals(offset: int = 0, limit: int = 100) -> list[int]:
```
Get ordinal numbers of all entry points.

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[int]</span>**: List of all export ordinal numbers.


### entries_get_start

```function
def entries_get_start() -> EntryData:
```
Get the main program entry point (start address).

**Returns:**
- **<span class='return-type'>EntryData</span>**: EntryInfo for the program's initial execution point.


### entries_rename

```function
def entries_rename(ordinal: int, new_name: str) -> bool:
```
Change the name of an entry point.

**Args:**
- **<span class='parameter'>ordinal</span>** (**<span class='return-type'>int</span>**): Ordinal number of entry to rename.
- **<span class='parameter'>new_name</span>** (**<span class='return-type'>str</span>**): New export name to assign.

**Returns:**
- **<span class='return-type'>bool</span>**: True if rename succeeded, False otherwise.


### entries_set_forwarder

```function
def entries_set_forwarder(ordinal: int, forwarder_name: str) -> bool:
```
Set DLL forwarding for an export.

**Args:**
- **<span class='parameter'>ordinal</span>** (**<span class='return-type'>int</span>**): Ordinal of entry to forward.
- **<span class='parameter'>forwarder_name</span>** (**<span class='return-type'>str</span>**): Target DLL and function (e.g., "KERNEL32.CreateFileA").

**Returns:**
- **<span class='return-type'>bool</span>**: True if forwarder was set successfully.
