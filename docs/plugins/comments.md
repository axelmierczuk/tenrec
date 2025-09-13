# Comments

Plugin to manage comments in the IDA database.

## Purpose
Manage comments in the IDA database including regular, repeatable, and function comments.

## Interaction Style
- Write comments that add value to understanding the code
- Use clear, concise comment text
- Choose appropriate comment type: REGULAR ("regular"), REPEATABLE ("repeatable"), or ALL ("all")

## Examples
- Add a regular comment at an offset: `comments_set(0x401000, "Entry point initialization", "regular")`
- Search comments for comments with regex: `comments_get_all_filtered("API.*call", "repeatable")`
- Get the comments in function 0x401000: `comments_get(0x401000, "all")`

## Anti-Examples
- DON'T use comments for storing structured data (use appropriate data types instead)
- DON'T create excessively long comments that obscure the disassembly
- DON'T forget that REPEATABLE comments propagate to all references




## Tools

### comments_delete

```function
def comments_delete(
    address: HexEA,
    comment_kind: CommentKind = CommentKind.REGULAR
) -> str:
```
Delete a comment at the specified address.

**Args:**
- **<span class='parameter'>address</span>** (**<span class='return-type'>HexEA</span>**): Address where the comment is located.
- **<span class='parameter'>comment_kind</span>** (**<span class='return-type'>CommentKind</span>**): Type of comment to delete:
	 - `REGULAR`: "regular"
	 - `REPEATABLE`: "repeatable"
	 - `ALL`: "all"

**Returns:**
- **<span class='return-type'>str</span>**: True if comment was deleted, False if no comment existed.


### comments_get

```function
def comments_get(
    address: HexEA,
    comment_kind: CommentKind = CommentKind.REGULAR
) -> CommentData:
```
Get a specific type of comment at an address.

**Args:**
- **<span class='parameter'>address</span>** (**<span class='return-type'>HexEA</span>**): Address to retrieve comment from.
- **<span class='parameter'>comment_kind</span>** (**<span class='return-type'>CommentKind</span>**): Type of comment to delete:
	 - `REGULAR`: "regular"
	 - `REPEATABLE`: "repeatable"
	 - `ALL`: "all"

**Returns:**
- **<span class='return-type'>CommentData</span>**: CommentInfo object containing comment text and metadata.


### comments_get_all

```function
def comments_get_all(
    comment_kind: CommentKind = CommentKind.REGULAR,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.CommentData]:
```
Get all comments of a specific type in the database.

**Args:**
- **<span class='parameter'>comment_kind</span>** (**<span class='return-type'>CommentKind</span>**): Type of comment to delete:
	 - `REGULAR`: "regular"
	 - `REPEATABLE`: "repeatable"
	 - `ALL`: "all"
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.CommentData]</span>**: List of CommentInfo objects for all comments of the specified type.


### comments_get_all_filtered

```function
def comments_get_all_filtered(
    search: str,
    comment_kind: CommentKind = CommentKind.REGULAR,
    offset: int = 0,
    limit: int = 100
) -> list[tenrec.plugins.models.ida.CommentData]:
```
Search for comments matching a regex pattern.

**Args:**
- **<span class='parameter'>search</span>** (**<span class='return-type'>str</span>**): Regular expression pattern to match comment text.
- **<span class='parameter'>comment_kind</span>** (**<span class='return-type'>CommentKind</span>**): Type of comment to delete:
	 - `REGULAR`: "regular"
	 - `REPEATABLE`: "repeatable"
	 - `ALL`: "all"
- **<span class='parameter'>offset</span>** (**<span class='return-type'>int</span>**)
- **<span class='parameter'>limit</span>** (**<span class='return-type'>int</span>**)

**Returns:**
- **<span class='return-type'>list[tenrec.plugins.models.ida.CommentData]</span>**: List of CommentInfo objects for comments matching the pattern.


### comments_set

```function
def comments_set(
    address: HexEA,
    comment: str,
    comment_kind: CommentKind = CommentKind.REGULAR
) -> bool:
```
Set or update a comment at an address.

**Args:**
- **<span class='parameter'>address</span>** (**<span class='return-type'>HexEA</span>**): Address where to place the comment.
- **<span class='parameter'>comment</span>** (**<span class='return-type'>str</span>**): Comment text to set (empty string to delete).
- **<span class='parameter'>comment_kind</span>** (**<span class='return-type'>CommentKind</span>**): Type of comment to delete:
	 - `REGULAR`: "regular"
	 - `REPEATABLE`: "repeatable"
	 - `ALL`: "all"

**Returns:**
- **<span class='return-type'>bool</span>**: True if comment was successfully set, False otherwise.
