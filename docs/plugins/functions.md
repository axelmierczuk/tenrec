# Functions

Plugin to analyze and manage functions in the IDA Pro database.

## Purpose
Analyze and manage functions in the binary including their boundaries, attributes, and relationships. Use for control flow analysis, function identification, and code structure understanding.

## Interaction Style
- Be extremely cautious when creating or modifying functions, always very with the client if unsure
- Use meaningful function names following conventions - snake_case for functions and variables, CamelCase for types and classes, g_ prefix for globals, s_ prefix for statics
- Be aware of function boundaries and overlaps

## Examples
- Get details on a function at 0x401000: `functions_get_at(0x401000)`
- Find by name: `functions_get_by_name("main")`
- Get pseudocode the pseudocode at function 0x401000: `functions_get_pseudocode(0x401000)`

## Anti-Examples
- DON'T create overlapping functions without checking boundaries
- DON'T assume function names are unique
- DON'T modify function boundaries without understanding call flow




## Tools

### functions_get_all

```function
def functions_get_all(
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.FunctionData]:
```
Retrieves all functions in the IDA Pro database.

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.FunctionData]</span>**: List of all functions as FunctionData objects containing metadata like name, address, size, and attributes.


### functions_get_all_filtered

```function
def functions_get_all_filtered(
    search: str,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.FunctionData]:
```
Retrieves functions matching a regex pattern from the database.

**Args:**
- **<span class='parameter'>search</span>** (**<span class='return-type'>str</span>**): Regular expression pattern to match against function names.
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.FunctionData]</span>**: List of functions whose names match the regex pattern as FunctionData objects.


### functions_get_at

```function
def functions_get_at(
    function_address: HexEA
) -> FunctionData:
```
Retrieves the function at the specified memory address.

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The effective address (EA) where the function is located.

**Returns:**
- **<span class='return-type'>FunctionData</span>**: FunctionData object containing the function at the specified address.


### functions_get_between

```function
def functions_get_between(
    function_start_address: HexEA,
    function_end_address: HexEA,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.FunctionData]:
```
Retrieves all functions within the specified address range.

**Args:**
- **<span class='parameter'>function_start_address</span>** (**<span class='return-type'>HexEA</span>**): Start address of the range (inclusive).
- **<span class='parameter'>function_end_address</span>** (**<span class='return-type'>HexEA</span>**): End address of the range (exclusive).
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.FunctionData]</span>**: List of functions whose start addresses fall within the range as FunctionData objects.


### functions_get_by_name

```function
def functions_get_by_name(function_name: str) -> FunctionData:
```
Retrieves a function by its exact name.

**Args:**
- **<span class='parameter'>function_name</span>** (**<span class='return-type'>str</span>**): Exact name of the function to retrieve.

**Returns:**
- **<span class='return-type'>FunctionData</span>**: FunctionData object containing the function's metadata and properties.


### functions_get_callees

```function
def functions_get_callees(
    function_address: HexEA,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.FunctionData]:
```
Retrieves all functions directly called by the function at the specified address (outgoing edges in call graph).

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The effective address of the calling function.
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.FunctionData]</span>**: List of functions called by this function as FunctionData objects.


### functions_get_callers

```function
def functions_get_callers(
    function_address: HexEA,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.FunctionData]:
```
Retrieves all functions that call the function at the specified address (incoming edges in call graph).

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The effective address of the target function.
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.FunctionData]</span>**: List of functions that call this function as FunctionData objects.


### functions_get_pseudocode

```function
def functions_get_pseudocode(
    function_address: HexEA,
    remove_tags: bool = True
) -> str:
```
Retrieves the decompiled C-like pseudocode of the function at the specified address.

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The effective address of the function to decompile.
- **<span class='parameter'>remove_tags</span>** (**<span class='return-type'>bool</span>**): Whether to remove IDA color/formatting tags for clean text output (default: True).

**Returns:**
- **<span class='return-type'>str</span>**: Decompiled pseudocode as a newline-separated string.


### functions_get_signature

```function
def functions_get_signature(
    function_address: HexEA
) -> str:
```
Retrieves the function prototype/signature at the specified address.

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The effective address of the function.

**Returns:**
- **<span class='return-type'>str</span>**: Function signature string with return type and parameters (e.g., "int func(void *arg1, int arg2)").


### functions_rename_local_variable

```function
def functions_rename_local_variable(
    function_address: HexEA,
    old_name: str,
    new_name: str
) -> str:
```
Rename a local variable in a function.

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The address of the function
- **<span class='parameter'>old_name</span>** (**<span class='return-type'>str</span>**): The old name of the local variable
- **<span class='parameter'>new_name</span>** (**<span class='return-type'>str</span>**): The new name of the local variable

**Returns:**
- **<span class='return-type'>str</span>**: 


### functions_set_name

```function
def functions_set_name(
    function_address: HexEA,
    name: str,
    auto_correct: bool = True
) -> bool:
```
Sets the name of the function at the specified address.

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The effective address of the function to rename.
- **<span class='parameter'>name</span>** (**<span class='return-type'>str</span>**): The new name to assign to the function.
- **<span class='parameter'>auto_correct</span>** (**<span class='return-type'>bool</span>**): Whether to automatically fix invalid characters in the name (default: True).

**Returns:**
- **<span class='return-type'>bool</span>**: True if rename succeeded, False if failed.
