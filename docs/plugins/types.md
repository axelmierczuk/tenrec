# Types

Plugin to manage type information in the IDA database including structures, unions, enums, functions, and typedefs.

## Purpose
Manage type information in the IDA database including structures, unions, enums, functions, and typedefs. Use for declaring custom types and retrieving type metadata.

## Interaction Style
- Provide complete C declarations with proper syntax
- Use standard C type notation (struct, union, enum, typedef)
- Include semicolons in declarations

## Examples
- Declare a struct: `types_declare_c_type("struct MyData { int id; char name[32]; };")`
- Declare typedef: `types_declare_c_type("typedef unsigned long DWORD;")`
- List all types: `types_list_local_types()` returns rich metadata for each type

## Anti-Examples
- DON'T declare incomplete or syntactically invalid types
- DON'T forget semicolons at the end of declarations
- DON'T declare conflicting type names without checking existing types




## Tools

### types_declare_c_type

```function
def types_declare_c_type(c_declaration: str) -> str:
```
Declares a C declaration type.

**Args:**
- **<span class='parameter'>c_declaration</span>** (**<span class='return-type'>str</span>**): The C declaration

**Returns:**
- **<span class='return-type'>str</span>**: 


### types_list_local_types

```function
def types_list_local_types(offset: int = 0, limit: int = 100) -> list[dict]:
```
Enumerate local types (TIL/IDATI) with rich, structured metadata.

Returns items shaped like:
```json
{
"ordinal": int,
"name": str,
"kind": str,  # "struct" | "union" | "enum" | "func" | "typedef" | "ptr" | "array" | "builtin" | "unknown"
"size": int | None,  # size in bytes if known
"decl_simple": str | None,  # 1-line C-ish declaration
"decl_full": str
| None,  # multi-line C declaration (with fields/args when available)
"details": {
...
},  # kind-specific details (members, enum values, func args/ret, etc.)
}
```

**Args:**
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[dict]</span>**: A list of dictionaries with type information.


### types_set_function_prototype

```function
def types_set_function_prototype(
    function_address: HexEA,
    prototype: str
) -> str:
```
Set a function prototype.

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The address of the function
- **<span class='parameter'>prototype</span>** (**<span class='return-type'>str</span>**): The prototype

**Returns:**
- **<span class='return-type'>str</span>**: 


### types_set_global_variable_type

```function
def types_set_global_variable_type(
    variable_address: HexEA,
    new_type: str
) -> str:
```
Set the global variable's type.

**Args:**
- **<span class='parameter'>variable_address</span>** (**<span class='return-type'>HexEA</span>**): The address of the global variable
- **<span class='parameter'>new_type</span>** (**<span class='return-type'>str</span>**): The new type of the global variable

**Returns:**
- **<span class='return-type'>str</span>**: 


### types_set_local_variable_type

```function
def types_set_local_variable_type(
    function_address: HexEA,
    variable_name: str,
    new_type: str
) -> str:
```
Set the local variable's type in a function.

**Args:**
- **<span class='parameter'>function_address</span>** (**<span class='return-type'>HexEA</span>**): The function address
- **<span class='parameter'>variable_name</span>** (**<span class='return-type'>str</span>**): The name of the local variable
- **<span class='parameter'>new_type</span>** (**<span class='return-type'>str</span>**): The new type of the local variable

**Returns:**
- **<span class='return-type'>str</span>**: 
