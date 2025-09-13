# Server

Manages multiple IDA database sessions and coordinates plugin operations.

## Purpose
Manages multiple IDA database sessions and coordinates plugin operations.

## Interaction Style
- Be concise. Prefer bullet points. Show short code in fenced blocks with language hints.
- Always specify addresses in hexadecimal format (e.g., '0x401000').
- Once you have a session, you will want to begin your analysis.
- Identify key functions using the `functions` plugin, focusing on the start function identified by IDA, as well as other functions of interest.
- From the functions, generate pseudo-code, and identify function calls and cross-references using the `xrefs` plugin.
- Rename global and local variables using the `names` plugin to rename them to meaningful names.
- Annotate functions, variables, and code blocks with comments using the `comments` plugin to provide context and explanations.
- Do NOT guess addresses or fabricate disassembly. If unsure, ask for a clarifying address or use the plugins provided.

## Examples
- Create a new session: `server_new_session(file='path/to/binary')`
- List all sessions: `server_list_sessions()`
- Switch to a session: `server_set_session(session_id='session_id')`
- Remove a session: `server_remove_session(session_id='session_id')`

## Anti-Examples
- DON'T attempt to analyze or modify the database directly.
- DON'T guess addresses or fabricate disassembly.




## Tools

### server_list_sessions

```function
def server_list_sessions() -> dict[str, list[Any]]:
```
List all sessions.

**Returns:**
- **<span class='return-type'>dict[str, list[Any]]</span>**: A list of session metadata.


### server_new_session

```function
def server_new_session(
    file: str,
    options: ida_domain.database.IdaCommandOptions | None = None
) -> dict:
```
Creates a new session from the given file.

**Args:**
- **<span class='parameter'>file</span>** (**<span class='return-type'>str</span>**): The file to create the session from.
- **<span class='parameter'>options</span>** (**<span class='return-type'>ida_domain.database.IdaCommandOptions | None</span>**): The options to use for the session.

**Returns:**
- **<span class='return-type'>dict</span>**: Session metadata.


### server_remove_all_sessions

```function
def server_remove_all_sessions():
```
Remove all sessions.


### server_remove_session

```function
def server_remove_session(session_id: str) -> bool:
```
Remove the given session.

**Args:**
- **<span class='parameter'>session_id</span>** (**<span class='return-type'>str</span>**): The id of the session to close.

**Returns:**
- **<span class='return-type'>bool</span>**: True if the session was removed, False otherwise.


### server_set_session

```function
def server_set_session(session_id: str) -> dict:
```
Open the given session.

**Args:**
- **<span class='parameter'>session_id</span>** (**<span class='return-type'>str</span>**): The id of the session to open.

**Returns:**
- **<span class='return-type'>dict</span>**: Session metadata.
