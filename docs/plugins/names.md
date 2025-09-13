# Names

Plugin to manage symbol names, labels, and identifiers in the binary.

## Purpose
Manage symbol names, labels, and identifiers in the binary. Use for renaming functions, variables, and locations to improve code readability.

## Interaction Style
- Use meaningful, descriptive names
- Use meaningful function names following conventions - snake_case for functions and variables, CamelCase for types and classes, g_ prefix for globals, s_ prefix for statics
- If a name is not found, you likely need to set it first. For example, dword_ and loc_ names are auto-generated and need to be renamed based on their address

## Examples
- Set the name of a symbol at an address: `names_set(0x401000, "process_input")`
- Find a symbol by name: `names_get_by_name("malloc")`
- Demangle a name: `names_demangle_name("_ZN4TestC1Ev")`

## Anti-Examples
- DON'T use reserved keywords as names
- DON'T create duplicate names
- DON'T use special characters that break naming rules




## Tools

### names_delete

```function
def names_delete(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Delete the name/label at the specified address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Linear address where the name is located.

**Returns:**
- **<span class='return-type'>bool</span>**: True if name was successfully deleted, False if no name existed or deletion failed.


### names_demangle_name

```function
def names_demangle_name(
    name: str,
    disable_mask: int | ida_domain.names.DemangleFlags = 0
) -> str:
```
Demangle a C++ or other mangled symbol name to human-readable form.

**Args:**
- **<span class='parameter'>name</span>** (**<span class='return-type'>str</span>**): Mangled symbol name (e.g., "_ZN5MyApp4initEv").
- **<span class='parameter'>disable_mask</span>** (**<span class='return-type'>int | ida_domain.names.DemangleFlags</span>**): Flags to control demangling output (DemangleFlags enum or raw int).

**Returns:**
- **<span class='return-type'>str</span>**: Demangled name string or original name if demangling failed.


### names_force_name

```function
def names_force_name(
    ea: HexEA,
    name: str,
    flags: int | ida_domain.names.SetNameFlags = 1
) -> bool:
```
Force assignment of a name at address, auto-numbering if name already exists elsewhere.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Linear address to name.
- **<span class='parameter'>name</span>** (**<span class='return-type'>str</span>**): Desired name (will be suffixed with _1, _2, etc. if needed).
- **<span class='parameter'>flags</span>** (**<span class='return-type'>int | ida_domain.names.SetNameFlags</span>**): Name setting flags (SetNameFlags enum or raw int, default: NOCHECK).

**Returns:**
- **<span class='return-type'>bool</span>**: True if name was successfully set (possibly with suffix), False otherwise.


### names_get_all

```function
def names_get_all(
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.NameData]:
```
Retrieves all named locations in the IDA Pro database.

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.NameData]</span>**: List of NameData objects containing address and name pairs for all named locations.


### names_get_all_filtered

```function
def names_get_all_filtered(
    search: str,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.NameData]:
```
Search for named locations matching a regex pattern.

**Args:**
- **<span class='parameter'>search</span>** (**<span class='return-type'>str</span>**): Regular expression pattern to match against names.
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.NameData]</span>**: List of NameData objects for names matching the pattern.


### names_get_at

```function
def names_get_at(ea: tenrec.plugins.models.ida.HexEA) -> NameData:
```
Get the name/label at a specific address. This is useful for checking dwork_, byte_, loc_, sub_ names.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to query.

**Returns:**
- **<span class='return-type'>NameData</span>**: NameData object containing the address and name.


### names_get_at_index

```function
def names_get_at_index(index: int) -> NameData:
```
Get a named element by its index in the names array.

**Args:**
- **<span class='parameter'>index</span>** (**<span class='return-type'>int</span>**): Zero-based index into the sorted names list.

**Returns:**
- **<span class='return-type'>NameData</span>**: NameData object containing address and name at the given index.


### names_get_count

```function
def names_get_count() -> int:
```
Get the total count of named locations in the database.

**Returns:**
- **<span class='return-type'>int</span>**: Integer count of all named addresses.


### names_get_demangled_name

```function
def names_get_demangled_name(
    ea: HexEA,
    inhibitor: DemangleFlags,
    demangling_format_flags: int = 0
) -> NameData:
```
Get the demangled version of a name at a specific address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Linear address with a mangled name.
- **<span class='parameter'>inhibitor</span>** (**<span class='return-type'>DemangleFlags</span>**): Flags to control demangling output (DemangleFlags enum).
- **<span class='parameter'>demangling_format_flags</span>** (**<span class='return-type'>int</span>**): Additional demangling format flags.

**Returns:**
- **<span class='return-type'>NameData</span>**: NameData with demangled name if available.


### names_set_name

```function
def names_set_name(
    ea: HexEA,
    name: str,
    flags: int | ida_domain.names.SetNameFlags = 1
) -> bool:
```
Set or delete a name/label at the specified address.

This is useful for renaming functions, variables, or locations such as dword_, byte_, loc_, sub_ names.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Linear address to name.
- **<span class='parameter'>name</span>** (**<span class='return-type'>str</span>**): New name to assign (empty string to delete existing name).
- **<span class='parameter'>flags</span>** (**<span class='return-type'>int | ida_domain.names.SetNameFlags</span>**): Name setting flags (SetNameFlags enum or raw int, default: NOCHECK).

**Returns:**
- **<span class='return-type'>bool</span>**: True if name was successfully set or deleted, False if operation failed.
