# Bytes

Plugin for managing raw bytes, data definitions, and low-level memory operations in the IDA database.

## Purpose
Manage raw bytes, data definitions, and low-level memory operations in the IDA database. Use for creating data types, searching patterns, and manipulating byte-level representations.

## Interaction Style
- Should typically only be used to confirm global variables or static data, not for local stack variables
- Be very careful when creating or modifying data types, prompt for confirmation if unsure
- Be explicit about data types and sizes

## Examples
- Create a string at the address 0x401000: `bytes_create_data_at(0x401000, "string")`
- Search pattern for the bytes 488B89 between 0x400000, 0x500000: `bytes_find_bytes_between("488B89", 0x400000, 0x500000)`
- Read 16 bytes at location 0x401000: `bytes_get_bytes(0x401000, 16)`

## Anti-Examples
- DON'T guess byte patterns without verification
- DON'T patch bytes without understanding their context
- DON'T create overlapping data definitions without force=True




## Tools

### bytes_check_flags_at

```function
def bytes_check_flags_at(
    ea: HexEA,
    flag_mask: ByteFlags
) -> bool:
```
Check if specific byte flags are set at an address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to check.
- **<span class='parameter'>flag_mask</span>** (**<span class='return-type'>ByteFlags</span>**): ByteFlags enum values to verify (can be OR'd together).

**Returns:**
- **<span class='return-type'>bool</span>**: True if ALL specified flags are set, False otherwise.


### bytes_create_data_at

```function
def bytes_create_data_at(
    ea: HexEA,
    data_type: DataType,
    count: int = 1,
    force: bool = False,
    length: int | None = None,
    string_type: StringType = C,
    tid: int | None = None,
    alignment: int = 0
) -> bool:
```
Create data items of specified type at consecutive addresses.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Starting address for data definitions.
- **<span class='parameter'>data_type</span>** (**<span class='return-type'>DataType</span>**): Type of data to create (DataType enum). Options are:
	 - `BYTE`: *byte (1 byte)*
	 - `WORD`: *word (2 bytes)*
	 - `DWORD`: *dword (4 bytes)*
	 - `QWORD`: *qword (8 bytes)*
	 - `OWORD`: *oword (16 bytes)*
	 - `YWORD`: *yword (32 bytes)*
	 - `ZWORD`: *zword (48 bytes)*
	 - `TBYTE`: *tbyte (10 bytes)*
	 - `FLOAT`: *float (4 bytes)*
	 - `DOUBLE`: *double (8 bytes)*
	 - `PACKED_REAL`: *packed_real (10 bytes)*
	 - `STRING`: *string (variable length, requires length parameter)*
	 - `STRUCT`: *struct (requires tid parameter for structure type)*
	 - `ALIGNMENT`: *alignment (requires length or alignment parameter)*
- **<span class='parameter'>count</span>** (**<span class='return-type'>int</span>**): Number of consecutive elements to create.
- **<span class='parameter'>force</span>** (**<span class='return-type'>bool</span>**): Override existing data definitions if True.
- **<span class='parameter'>length</span>** (**<span class='return-type'>int | None</span>**): Length parameter for strings and alignment types.
- **<span class='parameter'>string_type</span>** (**<span class='return-type'>StringType</span>**): String encoding type (for DataType.STRING). Options are:
	 - `C`: *0 (C-style null-terminated string, default)*
	 - `C_16`: *1 (C-style 16-bit string)*
	 - `C_32`: *2 (C-style 32-bit string)*
	 - `PASCAL`: *4 (Pascal-style string)*
	 - `PASCAL_16`: *5 (Pascal-style 16-bit string)*
	 - `PASCAL_32`: *6 (Pascal-style 32-bit string)*
	 - `LEN2`: *8 (String with 2-byte length prefix)*
	 - `LEN2_16`: *9 (16-bit string with 2-byte length prefix)*
	 - `LEN2_32`: *10 (32-bit string with 2-byte length prefix)*
- **<span class='parameter'>tid</span>** (**<span class='return-type'>int | None</span>**): Structure type ID (for DataType.STRUCT).
- **<span class='parameter'>alignment</span>** (**<span class='return-type'>int</span>**): Power of 2 alignment (for DataType.ALIGNMENT).

**Returns:**
- **<span class='return-type'>bool</span>**: True if data was successfully defined, False otherwise.


### bytes_delete_value_at

```function
def bytes_delete_value_at(ea: tenrec.plugins.models.ida.HexEA):
```
Mark an address as uninitialized by deleting its value.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to uninitialize.


### bytes_find_bytes_between

```function
def bytes_find_bytes_between(
    pattern: str,
    start_ea: HexEA = None,
    end_ea: HexEA = None,
    offset: int = 0,
    limit: int = 100
) -> HexEA:
```
Search for a byte pattern in memory.

**Args:**
- **<span class='parameter'>pattern</span>** (**<span class='return-type'>str</span>**): Byte sequence to find (e.g., b'9090' for two NOPs).
- **<span class='parameter'>start_ea</span>** (**<span class='return-type'>HexEA</span>**): Search start address (None for database start).
- **<span class='parameter'>end_ea</span>** (**<span class='return-type'>HexEA</span>**): Search end address (None for database end).
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>HexEA</span>**: HexEA address of first match.


### bytes_find_immediate_between

```function
def bytes_find_immediate_between(
    value: int,
    start_ea: HexEA = None,
    end_ea: HexEA = None
) -> HexEA:
```
Search for an immediate value used in instructions.

**Args:**
- **<span class='parameter'>value</span>** (**<span class='return-type'>int</span>**): Numeric immediate value to find (e.g., 0x1234).
- **<span class='parameter'>start_ea</span>** (**<span class='return-type'>HexEA</span>**): Search start address (None for database start).
- **<span class='parameter'>end_ea</span>** (**<span class='return-type'>HexEA</span>**): Search end address (None for database end).

**Returns:**
- **<span class='return-type'>HexEA</span>**: HexEA address of instruction containing the immediate.


### bytes_find_text_between

```function
def bytes_find_text_between(
    text: str,
    start_ea: HexEA = None,
    end_ea: HexEA = None,
    flags: SearchFlags = 1
) -> HexEA:
```
Search for text string in disassembly, comments, or data.

**Args:**
- **<span class='parameter'>text</span>** (**<span class='return-type'>str</span>**): Text string to find.
- **<span class='parameter'>start_ea</span>** (**<span class='return-type'>HexEA</span>**): Search start address (None for database start).
- **<span class='parameter'>end_ea</span>** (**<span class='return-type'>HexEA</span>**): Search end address (None for database end).
- **<span class='parameter'>flags</span>** (**<span class='return-type'>SearchFlags</span>**): Search direction and options (default: SearchFlags.DOWN).

**Returns:**
- **<span class='return-type'>HexEA</span>**: HexEA address where text was found.


### bytes_get_all_flags_at

```function
def bytes_get_all_flags_at(ea: tenrec.plugins.models.ida.HexEA) -> ByteFlags:
```
Get all byte flags at an address (type, attributes, etc.).

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to query.

**Returns:**
- **<span class='return-type'>ByteFlags</span>**: ByteFlags enum containing all flag bits set at address.


### bytes_get_bytes_at

```function
def bytes_get_bytes_at(ea: tenrec.plugins.models.ida.HexEA, size: int) -> str:
```
Read multiple bytes from memory as hex string.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Starting address to read from.
- **<span class='parameter'>size</span>** (**<span class='return-type'>int</span>**): Number of bytes to read.

**Returns:**
- **<span class='return-type'>str</span>**: Hex string representation of bytes (e.g., "909090" for three NOPs).


### bytes_get_data_size_at

```function
def bytes_get_data_size_at(ea: tenrec.plugins.models.ida.HexEA) -> int:
```
Get the size of a defined data item at address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address of the data item.

**Returns:**
- **<span class='return-type'>int</span>**: Size in bytes (1 for byte, 2 for word, 4 for dword, etc.).


### bytes_get_disassembly_at

```function
def bytes_get_disassembly_at(
    ea: HexEA,
    remove_tags: bool = True
) -> str:
```
Get disassembled instruction or data representation at address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to disassemble.
- **<span class='parameter'>remove_tags</span>** (**<span class='return-type'>bool</span>**): Strip IDA color/formatting tags if True.

**Returns:**
- **<span class='return-type'>str</span>**: Disassembly line as string (e.g., "mov eax, ebx" or "db 90h").


### bytes_get_flags_at

```function
def bytes_get_flags_at(ea: tenrec.plugins.models.ida.HexEA) -> ByteFlags:
```
Gets the flags for the specified address masked with IVL and MS_VAL.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.

**Returns:**
- **<span class='return-type'>ByteFlags</span>**: ByteFlags enum value representing the flags.


### bytes_get_next_address

```function
def bytes_get_next_address(ea: tenrec.plugins.models.ida.HexEA) -> HexEA:
```
Get the next valid address in the database.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Current address.

**Returns:**
- **<span class='return-type'>HexEA</span>**: HexEA of next valid address.


### bytes_get_next_head

```function
def bytes_get_next_head(
    ea: HexEA,
    max_ea: HexEA = None
) -> HexEA:
```
Find the next data item head (non-tail byte) after address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Current address.
- **<span class='parameter'>max_ea</span>** (**<span class='return-type'>HexEA</span>**): Stop searching at this address (None for database end).

**Returns:**
- **<span class='return-type'>HexEA</span>**: HexEA of next item head.


### bytes_get_original_bytes_at

```function
def bytes_get_original_bytes_at(
    ea: HexEA,
    size: int
) -> str:
```
Gets the original bytes before any patches by reading individual bytes.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.
- **<span class='parameter'>size</span>** (**<span class='return-type'>int</span>**): Number of bytes to read.

**Returns:**
- **<span class='return-type'>str</span>**: The original bytes as hex string.


### bytes_get_original_value_at

```function
def bytes_get_original_value_at(
    ea: HexEA,
    data_type: DataType
) -> int:
```
Get original value (before patching) at address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.
- **<span class='parameter'>data_type</span>** (**<span class='return-type'>DataType</span>**): Type of data to read (DataType enum).

**Returns:**
- **<span class='return-type'>int</span>**: The original value.


### bytes_get_previous_address

```function
def bytes_get_previous_address(ea: tenrec.plugins.models.ida.HexEA) -> HexEA:
```
Gets the previous valid address before the specified address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.

**Returns:**
- **<span class='return-type'>HexEA</span>**: Previous valid address.


### bytes_get_previous_head

```function
def bytes_get_previous_head(
    ea: HexEA,
    min_ea: HexEA = None
) -> HexEA:
```
Gets the previous head (start of data item) before the specified address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.
- **<span class='parameter'>min_ea</span>** (**<span class='return-type'>HexEA</span>**): Minimum address to search.

**Returns:**
- **<span class='return-type'>HexEA</span>**: Address of previous head.


### bytes_get_value_at

```function
def bytes_get_value_at(
    ea: HexEA,
    data_type: DataType,
    allow_uninitialized: bool = False
) -> int | float | str:
```
Read a value of specified type from memory.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to read from.
- **<span class='parameter'>data_type</span>** (**<span class='return-type'>DataType</span>**): Type of data to create (DataType enum). Options are:
	 - `BYTE`: *byte (1 byte)*
	 - `WORD`: *word (2 bytes)*
	 - `DWORD`: *dword (4 bytes)*
	 - `QWORD`: *qword (8 bytes)*
	 - `OWORD`: *oword (16 bytes)*
	 - `YWORD`: *yword (32 bytes)*
	 - `ZWORD`: *zword (48 bytes)*
	 - `TBYTE`: *tbyte (10 bytes)*
	 - `FLOAT`: *float (4 bytes)*
	 - `DOUBLE`: *double (8 bytes)*
	 - `PACKED_REAL`: *packed_real (10 bytes)*
	 - `STRING`: *string (variable length, requires length parameter)*
	 - `STRUCT`: *struct (requires tid parameter for structure type)*
	 - `ALIGNMENT`: *alignment (requires length or alignment parameter)*
- **<span class='parameter'>allow_uninitialized</span>** (**<span class='return-type'>bool</span>**): Allow reading uninitialized memory if True.

**Returns:**
- **<span class='return-type'>int | float | str</span>**: Value read from memory (type depends on data_type).


### bytes_has_any_flags_at

```function
def bytes_has_any_flags_at(
    ea: HexEA,
    flag_mask: ByteFlags
) -> bool:
```
Checks if any of the specified flags are set at the given address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.
- **<span class='parameter'>flag_mask</span>** (**<span class='return-type'>ByteFlags</span>**): ByteFlags enum value(s) to check.

**Returns:**
- **<span class='return-type'>bool</span>**: True if any of the specified flags are set, False otherwise.


### bytes_has_user_name_at

```function
def bytes_has_user_name_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Check if address has a user-defined (non-auto) name.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to check.

**Returns:**
- **<span class='return-type'>bool</span>**: True if user manually named this address, False for auto-generated names.


### bytes_is_code_at

```function
def bytes_is_code_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Check if address contains executable code.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to check.

**Returns:**
- **<span class='return-type'>bool</span>**: True if address is part of an instruction, False for data or undefined.


### bytes_is_data_at

```function
def bytes_is_data_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Check if address contains defined data (non-code).

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to check.

**Returns:**
- **<span class='return-type'>bool</span>**: True if address is defined as data, False for code or undefined.


### bytes_is_flowed_at

```function
def bytes_is_flowed_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Does the previous instruction exist and pass execution flow to the current byte?

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.

**Returns:**
- **<span class='return-type'>bool</span>**: True if flow, False otherwise.


### bytes_is_forced_operand_at

```function
def bytes_is_forced_operand_at(ea: tenrec.plugins.models.ida.HexEA, n: int) -> bool:
```
Is operand manually defined?

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.
- **<span class='parameter'>n</span>** (**<span class='return-type'>int</span>**): Operand number (0-based).

**Returns:**
- **<span class='return-type'>bool</span>**: True if operand is forced, False otherwise.


### bytes_is_head_at

```function
def bytes_is_head_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Check if address is the start of an instruction or data item.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to check.

**Returns:**
- **<span class='return-type'>bool</span>**: True if head byte, False if tail byte of multi-byte item.


### bytes_is_manual_insn_at

```function
def bytes_is_manual_insn_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Is the instruction overridden?

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.

**Returns:**
- **<span class='return-type'>bool</span>**: True if instruction is manually overridden, False otherwise.


### bytes_is_not_tail_at

```function
def bytes_is_not_tail_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Checks if the address is not a tail byte.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.

**Returns:**
- **<span class='return-type'>bool</span>**: True if not tail, False otherwise.


### bytes_is_tail_at

```function
def bytes_is_tail_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Check if address is a tail byte (continuation of multi-byte item).

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to check.

**Returns:**
- **<span class='return-type'>bool</span>**: True if tail byte of instruction/data, False if head or undefined.


### bytes_is_type_at

```function
def bytes_is_type_at(
    ea: HexEA,
    data_type: DataType
) -> bool:
```
Check if address contains a specific data type.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to check.
- **<span class='parameter'>data_type</span>** (**<span class='return-type'>DataType</span>**): Type of data to create (DataType enum). Options are:
	 - `BYTE`: *byte (1 byte)*
	 - `WORD`: *word (2 bytes)*
	 - `DWORD`: *dword (4 bytes)*
	 - `QWORD`: *qword (8 bytes)*
	 - `OWORD`: *oword (16 bytes)*
	 - `YWORD`: *yword (32 bytes)*
	 - `ZWORD`: *zword (48 bytes)*
	 - `TBYTE`: *tbyte (10 bytes)*
	 - `FLOAT`: *float (4 bytes)*
	 - `DOUBLE`: *double (8 bytes)*
	 - `PACKED_REAL`: *packed_real (10 bytes)*
	 - `STRING`: *string (variable length, requires length parameter)*
	 - `STRUCT`: *struct (requires tid parameter for structure type)*
	 - `ALIGNMENT`: *alignment (requires length or alignment parameter)*

**Returns:**
- **<span class='return-type'>bool</span>**: True if address contains the specified type, False otherwise.


### bytes_is_unknown_at

```function
def bytes_is_unknown_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Check if address is undefined/unexplored.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address to check.

**Returns:**
- **<span class='return-type'>bool</span>**: True if not yet defined as code or data, False if defined.


### bytes_is_value_initialized_at

```function
def bytes_is_value_initialized_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Check if the value at the specified address is initialized.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.

**Returns:**
- **<span class='return-type'>bool</span>**: True if byte is loaded, False otherwise.


### bytes_patch_value_at

```function
def bytes_patch_value_at(
    ea: HexEA,
    value: int | bytes,
    data_type: DataType = None
) -> bool:
```
Patch a value in the database (original value is preserved).

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): Address to patch.
- **<span class='parameter'>value</span>** (**<span class='return-type'>int | bytes</span>**): New value to write.
- **<span class='parameter'>data_type</span>** (**<span class='return-type'>DataType</span>**): Type of data to patch (auto-detect from value if None).

**Returns:**
- **<span class='return-type'>bool</span>**: True if patch applied, False otherwise.


### bytes_revert_byte_at

```function
def bytes_revert_byte_at(ea: tenrec.plugins.models.ida.HexEA) -> bool:
```
Revert patched byte to its original value.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.

**Returns:**
- **<span class='return-type'>bool</span>**: True if byte was patched before and reverted now, False otherwise.


### bytes_set_value_at

```function
def bytes_set_value_at(
    ea: HexEA,
    value: int | bytes,
    data_type: DataType = None
) -> bool:
```
Set a value at the specified address.

**Args:**
- **<span class='parameter'>ea</span>** (**<span class='return-type'>HexEA</span>**): The effective address.
- **<span class='parameter'>value</span>** (**<span class='return-type'>int | bytes</span>**): Value to set.
- **<span class='parameter'>data_type</span>** (**<span class='return-type'>DataType</span>**): Type of data to set (auto-detect from value if None).

**Returns:**
- **<span class='return-type'>bool</span>**: True if successful, False otherwise.
