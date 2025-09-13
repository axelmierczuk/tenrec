# Strings

Plugin for extracting and analyzing string literals in the binary.

## Purpose
Extract and analyze string literals in the binary. Use for finding hardcoded values, messages, URLs, and other text data.

## Interaction Style
- Use regex patterns for filtering
- Look for strings to help you understand code functionality and identify interesting locations

## Examples
- List all the strings: `strings_get_all()`
- Find URLs in strings: `strings_get_all_filtered("https?://")`

## Anti-Examples
- DON'T assume all text is valid strings
- DON'T ignore string encoding types
- DON'T overlook unicode strings




## Tools

### strings_get_all

```function
def strings_get_all() -> list[tenrec.plugins.models.ida.StringData]:
```
Get all strings extracted from the binary.

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.StringData]</span>**: List of StringInfo objects for all identified strings.


### strings_get_all_filtered

```function
def strings_get_all_filtered(
    search: str
) -> list[tenrec.plugins.models.ida.StringData]:
```
Search for strings matching a regex pattern.

**Args:**
- **<span class='parameter'>search</span>** (**<span class='return-type'>str</span>**): Regular expression pattern to match string content.

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.StringData]</span>**: List of StringInfo objects for strings matching the pattern.


### strings_get_at_address

```function
def strings_get_at_address(
    address: HexEA,
    offset: int = 0,
    limit: int = 100
) -> StringData:
```
Get detailed string information at a specific address.

**Args:**
- **<span class='parameter'>address</span>** (**<span class='return-type'>HexEA</span>**): Address where the string is located.
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>StringData</span>**: StringInfo object with string content, type, and length.


### strings_get_at_index

```function
def strings_get_at_index(
    index: int,
    offset: int = 0,
    limit: int = 100
) -> StringData:
```
Get string by its index in the string list.

**Args:**
- **<span class='parameter'>index</span>** (**<span class='return-type'>int</span>**): Zero-based index in the sorted string list.
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>StringData</span>**: StringInfo object for the string at this index.


### strings_get_between

```function
def strings_get_between(
    start: HexEA,
    end: HexEA
) -> list[tenrec.plugins.models.ida.StringData]:
```
Get all strings within an address range.

**Args:**
- **<span class='parameter'>start</span>** (**<span class='return-type'>HexEA</span>**): Start address (inclusive).
- **<span class='parameter'>end</span>** (**<span class='return-type'>HexEA</span>**): End address (exclusive).

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.StringData]</span>**: List of StringInfo objects for strings in the range.
