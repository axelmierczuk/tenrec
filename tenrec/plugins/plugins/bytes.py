from enum import Enum

from ida_domain.bytes import ByteFlags, SearchFlags
from ida_domain.strings import StringType

from tenrec.plugins.models import (
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)


BYTE_MAX = 0xFF
WORD_MAX = 0xFFFF
DWORD_MAX = 0xFFFFFFFF


class DataType(Enum):
    BYTE = "byte"
    WORD = "word"
    DWORD = "dword"
    QWORD = "qword"
    OWORD = "oword"
    YWORD = "yword"
    ZWORD = "zword"
    TBYTE = "tbyte"
    FLOAT = "float"
    DOUBLE = "double"
    PACKED_REAL = "packed_real"
    STRING = "string"
    STRUCT = "struct"
    ALIGNMENT = "alignment"


class BytesPlugin(PluginBase):
    """Plugin for managing raw bytes, data definitions, and low-level memory operations in the IDA database."""

    name = "bytes"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Manage raw bytes, data definitions, and low-level memory operations in the IDA database. Use for "
            "creating data types, searching patterns, and manipulating byte-level representations."
        ),
        interaction_style=[
            "Should typically only be used to confirm global variables or static data, not for local stack variables",
            "Be very careful when creating or modifying data types, prompt for confirmation if unsure",
            "Be explicit about data types and sizes",
        ],
        examples=[
            'Create a string at the address 0x401000: `bytes_create_data_at(0x401000, "string")`',
            (
                'Search pattern for the bytes 488B89 between 0x400000, 0x500000: `bytes_find_bytes_between("488B89", '
                "0x400000, 0x500000)`"
            ),
            "Read 16 bytes at location 0x401000: `bytes_get_bytes(0x401000, 16)`",
        ],
        anti_examples=[
            "DON'T guess byte patterns without verification",
            "DON'T patch bytes without understanding their context",
            "DON'T create overlapping data definitions without force=True",
        ],
    )

    @operation()
    def create_data_at(
        self,
        ea: HexEA,
        data_type: DataType,
        count: int = 1,
        force: bool = False,
        length: int | None = None,
        string_type: StringType = StringType.C,
        tid: int | None = None,
        alignment: int = 0,
    ) -> bool:
        """Create data items of specified type at consecutive addresses.

        :param ea: Starting address for data definitions.
        :param data_type: Type of data to create (DataType enum). Options are:
            `BYTE`: *byte (1 byte)*
            `WORD`: *word (2 bytes)*
            `DWORD`: *dword (4 bytes)*
            `QWORD`: *qword (8 bytes)*
            `OWORD`: *oword (16 bytes)*
            `YWORD`: *yword (32 bytes)*
            `ZWORD`: *zword (48 bytes)*
            `TBYTE`: *tbyte (10 bytes)*
            `FLOAT`: *float (4 bytes)*
            `DOUBLE`: *double (8 bytes)*
            `PACKED_REAL`: *packed_real (10 bytes)*
            `STRING`: *string (variable length, requires length parameter)*
            `STRUCT`: *struct (requires tid parameter for structure type)*
            `ALIGNMENT`: *alignment (requires length or alignment parameter)*
        :param count: Number of consecutive elements to create.
        :param force: Override existing data definitions if True.
        :param length: Length parameter for strings and alignment types.
        :param string_type: String encoding type (for DataType.STRING). Options are:
            `C`: *0 (C-style null-terminated string, default)*
            `C_16`: *1 (C-style 16-bit string)*
            `C_32`: *2 (C-style 32-bit string)*
            `PASCAL`: *4 (Pascal-style string)*
            `PASCAL_16`: *5 (Pascal-style 16-bit string)*
            `PASCAL_32`: *6 (Pascal-style 32-bit string)*
            `LEN2`: *8 (String with 2-byte length prefix)*
            `LEN2_16`: *9 (16-bit string with 2-byte length prefix)*
            `LEN2_32`: *10 (32-bit string with 2-byte length prefix)*
        :param tid: Structure type ID (for DataType.STRUCT).
        :param alignment: Power of 2 alignment (for DataType.ALIGNMENT).
        :return: True if data was successfully defined, False otherwise.
        """
        match data_type:
            case DataType.BYTE:
                return self.database.bytes.create_byte_at(ea.ea_t, count, force)
            case DataType.WORD:
                return self.database.bytes.create_word_at(ea.ea_t, count, force)
            case DataType.DWORD:
                return self.database.bytes.create_dword_at(ea.ea_t, count, force)
            case DataType.QWORD:
                return self.database.bytes.create_qword_at(ea.ea_t, count, force)
            case DataType.OWORD:
                return self.database.bytes.create_oword_at(ea.ea_t, count, force)
            case DataType.YWORD:
                return self.database.bytes.create_yword_at(ea.ea_t, count, force)
            case DataType.ZWORD:
                return self.database.bytes.create_zword_at(ea.ea_t, count, force)
            case DataType.TBYTE:
                return self.database.bytes.create_tbyte_at(ea.ea_t, count, force)
            case DataType.FLOAT:
                return self.database.bytes.create_float_at(ea.ea_t, count, force)
            case DataType.DOUBLE:
                return self.database.bytes.create_double_at(ea.ea_t, count, force)
            case DataType.PACKED_REAL:
                return self.database.bytes.create_packed_real_at(ea.ea_t, count, force)
            case DataType.STRING:
                return self.database.bytes.create_string_at(ea.ea_t, length, string_type)
            case DataType.STRUCT:
                if tid is None:
                    msg = "tid parameter required for struct creation"
                    raise OperationError(msg)
                return self.database.bytes.create_struct_at(ea.ea_t, count, tid, force)
            case DataType.ALIGNMENT:
                length_val = length if length is not None else 0
                return self.database.bytes.create_alignment_at(ea.ea_t, length_val, alignment)
            case _:
                msg = f"Unsupported data type: {data_type}"
                raise OperationError(msg)

    @operation()
    def get_value_at(self, ea: HexEA, data_type: DataType, allow_uninitialized: bool = False) -> int | float | str:
        """Read a value of specified type from memory.

        :param ea: The effective address to read from.
        :param data_type: Type of data to create (DataType enum). Options are:
            `BYTE`: *byte (1 byte)*
            `WORD`: *word (2 bytes)*
            `DWORD`: *dword (4 bytes)*
            `QWORD`: *qword (8 bytes)*
            `OWORD`: *oword (16 bytes)*
            `YWORD`: *yword (32 bytes)*
            `ZWORD`: *zword (48 bytes)*
            `TBYTE`: *tbyte (10 bytes)*
            `FLOAT`: *float (4 bytes)*
            `DOUBLE`: *double (8 bytes)*
            `PACKED_REAL`: *packed_real (10 bytes)*
            `STRING`: *string (variable length, requires length parameter)*
            `STRUCT`: *struct (requires tid parameter for structure type)*
            `ALIGNMENT`: *alignment (requires length or alignment parameter)*
        :param allow_uninitialized: Allow reading uninitialized memory if True.
        :return: Value read from memory (type depends on data_type).
        """
        match data_type:
            case DataType.BYTE:
                return self.database.bytes.get_byte_at(ea.ea_t, allow_uninitialized)
            case DataType.WORD:
                return self.database.bytes.get_word_at(ea.ea_t, allow_uninitialized)
            case DataType.DWORD:
                return self.database.bytes.get_dword_at(ea.ea_t, allow_uninitialized)
            case DataType.QWORD:
                return self.database.bytes.get_qword_at(ea.ea_t, allow_uninitialized)
            case DataType.FLOAT:
                result = self.database.bytes.get_float_at(ea.ea_t, allow_uninitialized)
                if result is None:
                    msg = f"Could not get float at '{ea}' in database"
                    raise OperationError(msg)
                return result
            case DataType.DOUBLE:
                result = self.database.bytes.get_double_at(ea.ea_t, allow_uninitialized)
                if result is None:
                    msg = f"Could not get double at '{ea}' in database"
                    raise OperationError(msg)
                return result
            case DataType.STRING:
                result = self.database.bytes.get_string_at(ea.ea_t)
                if result is None:
                    msg = f"Could not get string at '{ea}' in database"
                    raise OperationError(msg)
                return result
            case _:
                msg = f"Unsupported data type for reading: {data_type}"
                raise OperationError(msg)

    @operation()
    def is_type_at(self, ea: HexEA, data_type: DataType) -> bool:
        """Check if address contains a specific data type.

        :param ea: The effective address to check.
        :param data_type: Type of data to create (DataType enum). Options are:
            `BYTE`: *byte (1 byte)*
            `WORD`: *word (2 bytes)*
            `DWORD`: *dword (4 bytes)*
            `QWORD`: *qword (8 bytes)*
            `OWORD`: *oword (16 bytes)*
            `YWORD`: *yword (32 bytes)*
            `ZWORD`: *zword (48 bytes)*
            `TBYTE`: *tbyte (10 bytes)*
            `FLOAT`: *float (4 bytes)*
            `DOUBLE`: *double (8 bytes)*
            `PACKED_REAL`: *packed_real (10 bytes)*
            `STRING`: *string (variable length, requires length parameter)*
            `STRUCT`: *struct (requires tid parameter for structure type)*
            `ALIGNMENT`: *alignment (requires length or alignment parameter)*
        :return: True if address contains the specified type, False otherwise.
        """
        match data_type:
            case DataType.BYTE:
                return self.database.bytes.is_byte_at(ea.ea_t)
            case DataType.WORD:
                return self.database.bytes.is_word_at(ea.ea_t)
            case DataType.DWORD:
                return self.database.bytes.is_dword_at(ea.ea_t)
            case DataType.QWORD:
                return self.database.bytes.is_qword_at(ea.ea_t)
            case DataType.OWORD:
                return self.database.bytes.is_oword_at(ea.ea_t)
            case DataType.YWORD:
                return self.database.bytes.is_yword_at(ea.ea_t)
            case DataType.ZWORD:
                return self.database.bytes.is_zword_at(ea.ea_t)
            case DataType.TBYTE:
                return self.database.bytes.is_tbyte_at(ea.ea_t)
            case DataType.FLOAT:
                return self.database.bytes.is_float_at(ea.ea_t)
            case DataType.DOUBLE:
                return self.database.bytes.is_double_at(ea.ea_t)
            case DataType.PACKED_REAL:
                return self.database.bytes.is_packed_real_at(ea.ea_t)
            case DataType.STRING:
                return self.database.bytes.is_string_literal_at(ea.ea_t)
            case DataType.STRUCT:
                return self.database.bytes.is_struct_at(ea.ea_t)
            case DataType.ALIGNMENT:
                return self.database.bytes.is_alignment_at(ea.ea_t)

    @operation()
    def patch_value_at(self, ea: HexEA, value: int | bytes, data_type: DataType = None) -> bool:
        """Patch a value in the database (original value is preserved).

        :param ea: Address to patch.
        :param value: New value to write.
        :param data_type: Type of data to patch (auto-detect from value if None).
        :return: True if patch applied, False otherwise.
        """
        if isinstance(value, bytes):
            self.database.bytes.patch_bytes_at(ea.ea_t, value)
            return True

        if data_type is None:
            if 0 <= value <= BYTE_MAX:
                data_type = DataType.BYTE
            elif 0 <= value <= WORD_MAX:
                data_type = DataType.WORD
            elif 0 <= value <= DWORD_MAX:
                data_type = DataType.DWORD
            else:
                data_type = DataType.QWORD

        match data_type:
            case DataType.BYTE:
                return self.database.bytes.patch_byte_at(ea.ea_t, value)
            case DataType.WORD:
                return self.database.bytes.patch_word_at(ea.ea_t, value)
            case DataType.DWORD:
                return self.database.bytes.patch_dword_at(ea.ea_t, value)
            case DataType.QWORD:
                return self.database.bytes.patch_qword_at(ea.ea_t, value)
            case _:
                msg = f"Unsupported data type for patching: {data_type}"
                raise OperationError(msg)

    @operation()
    def set_value_at(self, ea: HexEA, value: int | bytes, data_type: DataType = None) -> bool:
        """Set a value at the specified address.

        :param ea: The effective address.
        :param value: Value to set.
        :param data_type: Type of data to set (auto-detect from value if None).
        :return: True if successful, False otherwise.
        """
        if isinstance(value, bytes):
            self.database.bytes.set_bytes_at(ea.ea_t, value)
            return True

        if data_type is None:
            if 0 <= value <= BYTE_MAX:
                data_type = DataType.BYTE
            elif 0 <= value <= WORD_MAX:
                data_type = DataType.WORD
            elif 0 <= value <= DWORD_MAX:
                data_type = DataType.DWORD
            else:
                data_type = DataType.QWORD

        match data_type:
            case DataType.BYTE:
                return self.database.bytes.set_byte_at(ea.ea_t, value)
            case DataType.WORD:
                self.database.bytes.set_word_at(ea.ea_t, value)
                return True
            case DataType.DWORD:
                self.database.bytes.set_dword_at(ea.ea_t, value)
                return True
            case DataType.QWORD:
                self.database.bytes.set_qword_at(ea.ea_t, value)
                return True
            case _:
                msg = f"Unsupported data type for setting: {data_type}"
                raise OperationError(msg)

    @operation()
    def get_original_value_at(self, ea: HexEA, data_type: DataType) -> int:
        """Get original value (before patching) at address.

        :param ea: The effective address.
        :param data_type: Type of data to read (DataType enum).
        :return: The original value.
        """
        result = None
        match data_type:
            case DataType.BYTE:
                result = self.database.bytes.get_original_byte_at(ea.ea_t)
            case DataType.WORD:
                result = self.database.bytes.get_original_word_at(ea.ea_t)
            case DataType.DWORD:
                result = self.database.bytes.get_original_dword_at(ea.ea_t)
            case DataType.QWORD:
                result = self.database.bytes.get_original_qword_at(ea.ea_t)
            case _:
                msg = f"Unsupported data type for getting original: {data_type}"
                raise OperationError(msg)
        if result is None:
            msg = f"Could not get original {data_type.value} at '{ea}' in database"
            raise OperationError(msg)
        return result

    @operation()
    def check_flags_at(self, ea: HexEA, flag_mask: ByteFlags) -> bool:
        """Check if specific byte flags are set at an address.

        :param ea: The effective address to check.
        :param flag_mask: ByteFlags enum values to verify (can be OR'd together).
        :return: True if ALL specified flags are set, False otherwise.
        """
        return self.database.bytes.check_flags_at(ea.ea_t, flag_mask)

    @operation()
    def delete_value_at(self, ea: HexEA) -> None:
        """Mark an address as uninitialized by deleting its value.

        :param ea: The effective address to uninitialize.
        """
        self.database.bytes.delete_value_at(ea.ea_t)

    @operation(options=[PaginatedParameter()])
    def find_bytes_between(self, pattern: str, start_ea: HexEA = None, end_ea: HexEA = None) -> HexEA:
        """Search for a byte pattern in memory.

        :param pattern: Byte sequence to find (e.g., b'9090' for two NOPs).
        :param start_ea: Search start address (None for database start).
        :param end_ea: Search end address (None for database end).
        :return: HexEA address of first match.
        :raises OperationException: If pattern not found.
        """
        caught_error = False
        try:
            pattern = bytes.fromhex(pattern)
        except (ValueError, TypeError):
            caught_error = True

        if caught_error:
            msg = "Pattern must be a hex string (e.g., '9090' for two NOPs)"
            raise OperationError(msg)

        result = self.database.bytes.find_bytes_between(pattern, start_ea.ea_t, end_ea.ea_t)
        if result is None:
            msg = f"Could not find byte pattern '{pattern}' in database"
            raise OperationError(msg)
        return HexEA(result)

    @operation()
    def find_immediate_between(self, value: int, start_ea: HexEA = None, end_ea: HexEA = None) -> HexEA:
        """Search for an immediate value used in instructions.

        :param value: Numeric immediate value to find (e.g., 0x1234).
        :param start_ea: Search start address (None for database start).
        :param end_ea: Search end address (None for database end).
        :return: HexEA address of instruction containing the immediate.
        :raises OperationException: If immediate value not found.
        """
        result = self.database.bytes.find_immediate_between(value, start_ea.ea_t, end_ea.ea_t)
        if result is None:
            msg = f"Could not find byte pattern '{value}' in database"
            raise OperationError(msg)
        return HexEA(result)

    @operation()
    def find_text_between(
        self, text: str, start_ea: HexEA = None, end_ea: HexEA = None, flags: SearchFlags = SearchFlags.DOWN
    ) -> HexEA:
        """Search for text string in disassembly, comments, or data.

        :param text: Text string to find.
        :param start_ea: Search start address (None for database start).
        :param end_ea: Search end address (None for database end).
        :param flags: Search direction and options (default: SearchFlags.DOWN).
        :return: HexEA address where text was found.
        :raises OperationException: If text not found.
        """
        result = self.database.bytes.find_text_between(text, start_ea.ea_t, end_ea.ea_t, flags)
        if result is None:
            msg = f"Could not find text '{text}' in database between '{start_ea}' and '{end_ea}'"
            raise OperationError(msg)
        return HexEA(result)

    @operation()
    def get_all_flags_at(self, ea: HexEA) -> ByteFlags:
        """Get all byte flags at an address (type, attributes, etc.).

        :param ea: The effective address to query.
        :return: ByteFlags enum containing all flag bits set at address.
        """
        return self.database.bytes.get_all_flags_at(ea.ea_t)

    @operation()
    def get_bytes_at(self, ea: HexEA, size: int) -> str:
        """Read multiple bytes from memory as hex string.

        :param ea: Starting address to read from.
        :param size: Number of bytes to read.
        :return: Hex string representation of bytes (e.g., "909090" for three NOPs).
        :raises OperationException: If read fails.
        """
        res = self.database.bytes.get_bytes_at(ea.ea_t, size)
        if res is None:
            msg = f"Could not get bytes at '{ea}' of size '{size}' in database"
            raise OperationError(msg)
        return res.hex()

    @operation()
    def get_data_size_at(self, ea: HexEA) -> int:
        """Get the size of a defined data item at address.

        :param ea: The effective address of the data item.
        :return: Size in bytes (1 for byte, 2 for word, 4 for dword, etc.).
        """
        return self.database.bytes.get_data_size_at(ea.ea_t)

    @operation()
    def get_disassembly_at(self, ea: HexEA, remove_tags: bool = True) -> str:
        """Get disassembled instruction or data representation at address.

        :param ea: The effective address to disassemble.
        :param remove_tags: Strip IDA color/formatting tags if True.
        :return: Disassembly line as string (e.g., "mov eax, ebx" or "db 90h").
        :raises OperationException: If disassembly fails.
        """
        result = self.database.bytes.get_disassembly_at(ea.ea_t, remove_tags)
        if result is None:
            msg = f"Could not get disassembly at '{ea}' in database"
            raise OperationError(msg)
        return result

    @operation()
    def get_flags_at(self, ea: HexEA) -> ByteFlags:
        """Gets the flags for the specified address masked with IVL and MS_VAL.

        :param ea: The effective address.
        :return: ByteFlags enum value representing the flags.
        """
        return self.database.bytes.get_flags_at(ea.ea_t)

    @operation()
    def get_next_address(self, ea: HexEA) -> HexEA:
        """Get the next valid address in the database.

        :param ea: Current address.
        :return: HexEA of next valid address.
        :raises OperationException: If no next address exists (end of database).
        """
        result = self.database.bytes.get_next_address(ea.ea_t)
        if result is None:
            msg = f"Could not get next address after '{ea}' in database"
            raise OperationError(msg)
        return HexEA(result)

    @operation()
    def get_next_head(self, ea: HexEA, max_ea: HexEA = None) -> HexEA:
        """Find the next data item head (non-tail byte) after address.

        :param ea: Current address.
        :param max_ea: Stop searching at this address (None for database end).
        :return: HexEA of next item head.
        :raises OperationException: If no next head found before max_ea.
        """
        result = self.database.bytes.get_next_head(ea.ea_t, max_ea)
        if result is None:
            msg = f"Could not get next head after '{ea}' in database"
            raise OperationError(msg)
        return HexEA(result)

    @operation()
    def get_original_bytes_at(self, ea: HexEA, size: int) -> str:
        """Gets the original bytes before any patches by reading individual bytes.

        :param ea: The effective address.
        :param size: Number of bytes to read.
        :return: The original bytes as hex string.
        :raises OperationException: If read fails.
        """
        res = self.database.bytes.get_original_bytes_at(ea.ea_t, size)
        if res is None:
            msg = f"Could not get original bytes at '{ea}' of size '{size}' in database"
            raise OperationError(msg)
        return res.hex()

    @operation()
    def get_previous_address(self, ea: HexEA) -> HexEA:
        """Gets the previous valid address before the specified address.

        :param ea: The effective address.
        :return: Previous valid address.
        :raises OperationException: If no previous address exists.
        """
        result = self.database.bytes.get_previous_address(ea.ea_t)
        if result is None:
            msg = f"Could not get previous address before '{ea}' in database"
            raise OperationError(msg)
        return HexEA(result)

    @operation()
    def get_previous_head(self, ea: HexEA, min_ea: HexEA = None) -> HexEA:
        """Gets the previous head (start of data item) before the specified address.

        :param ea: The effective address.
        :param min_ea: Minimum address to search.
        :return: Address of previous head.
        :raises OperationException: If no previous head found.
        """
        result = self.database.bytes.get_previous_head(ea.ea_t, min_ea)
        if result is None:
            msg = f"Could not get previous head before '{ea}' in database"
            raise OperationError(msg)
        return HexEA(result)

    @operation()
    def has_any_flags_at(self, ea: HexEA, flag_mask: ByteFlags) -> bool:
        """Checks if any of the specified flags are set at the given address.

        :param ea: The effective address.
        :param flag_mask: ByteFlags enum value(s) to check.
        :return: True if any of the specified flags are set, False otherwise.
        """
        return self.database.bytes.has_any_flags_at(ea.ea_t, flag_mask)

    @operation()
    def has_user_name_at(self, ea: HexEA) -> bool:
        """Check if address has a user-defined (non-auto) name.

        :param ea: The effective address to check.
        :return: True if user manually named this address, False for auto-generated names.
        """
        return self.database.bytes.has_user_name_at(ea.ea_t)

    @operation()
    def is_code_at(self, ea: HexEA) -> bool:
        """Check if address contains executable code.

        :param ea: The effective address to check.
        :return: True if address is part of an instruction, False for data or undefined.
        """
        return self.database.bytes.is_code_at(ea.ea_t)

    @operation()
    def is_data_at(self, ea: HexEA) -> bool:
        """Check if address contains defined data (non-code).

        :param ea: The effective address to check.
        :return: True if address is defined as data, False for code or undefined.
        """
        return self.database.bytes.is_data_at(ea.ea_t)

    @operation()
    def is_flowed_at(self, ea: HexEA) -> bool:
        """Does the previous instruction exist and pass execution flow to the current byte?

        :param ea: The effective address.
        :return: True if flow, False otherwise.
        """
        return self.database.bytes.is_flowed_at(ea.ea_t)

    @operation()
    def is_forced_operand_at(self, ea: HexEA, n: int) -> bool:
        """Is operand manually defined?

        :param ea: The effective address.
        :param n: Operand number (0-based).
        :return: True if operand is forced, False otherwise.
        """
        return self.database.bytes.is_forced_operand_at(ea.ea_t, n)

    @operation()
    def is_head_at(self, ea: HexEA) -> bool:
        """Check if address is the start of an instruction or data item.

        :param ea: The effective address to check.
        :return: True if head byte, False if tail byte of multi-byte item.
        """
        return self.database.bytes.is_head_at(ea.ea_t)

    @operation()
    def is_manual_insn_at(self, ea: HexEA) -> bool:
        """Is the instruction overridden?

        :param ea: The effective address.
        :return: True if instruction is manually overridden, False otherwise.
        """
        return self.database.bytes.is_manual_insn_at(ea.ea_t)

    @operation()
    def is_not_tail_at(self, ea: HexEA) -> bool:
        """Checks if the address is not a tail byte.

        :param ea: The effective address.
        :return: True if not tail, False otherwise.
        """
        return self.database.bytes.is_not_tail_at(ea.ea_t)

    @operation()
    def is_tail_at(self, ea: HexEA) -> bool:
        """Check if address is a tail byte (continuation of multi-byte item).

        :param ea: The effective address to check.
        :return: True if tail byte of instruction/data, False if head or undefined.
        """
        return self.database.bytes.is_tail_at(ea.ea_t)

    @operation()
    def is_unknown_at(self, ea: HexEA) -> bool:
        """Check if address is undefined/unexplored.

        :param ea: The effective address to check.
        :return: True if not yet defined as code or data, False if defined.
        """
        return self.database.bytes.is_unknown_at(ea.ea_t)

    @operation()
    def is_value_initialized_at(self, ea: HexEA) -> bool:
        """Check if the value at the specified address is initialized.

        :param ea: The effective address.
        :return: True if byte is loaded, False otherwise.
        """
        return self.database.bytes.is_value_initialized_at(ea.ea_t)

    @operation()
    def revert_byte_at(self, ea: HexEA) -> bool:
        """Revert patched byte to its original value.

        :param ea: The effective address.
        :return: True if byte was patched before and reverted now, False otherwise.
        """
        return self.database.bytes.revert_byte_at(ea.ea_t)


plugin = BytesPlugin()
