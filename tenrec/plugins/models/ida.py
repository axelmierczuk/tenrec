from enum import IntEnum

import ida_hexrays
from ida_domain.comments import CommentInfo
from ida_domain.entries import EntryInfo
from ida_domain.strings import StringItem, ea_t
from ida_domain.xrefs import XrefInfo
from ida_funcs import func_t
from ida_segment import segment_t
from idautils import ida_typeinf
from pydantic import BaseModel
from pydantic_core import core_schema as cs

from tenrec.plugins.models import OperationError


class SegmentType(IntEnum):
    """IDA segment type definitions."""

    SEG_NORM = 0  # unknown type, no assumptions
    SEG_XTRN = 1  # segment with 'extern' definitions
    SEG_CODE = 2  # code segment
    SEG_DATA = 3  # data segment
    SEG_IMP = 4  # java: implementation segment
    SEG_GRP = 6  # group of segments
    SEG_NULL = 7  # zero-length segment
    SEG_UNDF = 8  # undefined segment type (not used)
    SEG_BSS = 9  # uninitialized segment
    SEG_ABSSYM = 10  # segment with definitions of absolute symbols
    SEG_COMM = 11  # segment with communal definitions
    SEG_IMEM = 12  # internal processor memory & sfr (8051)
    SEG_MAX_SEGTYPE_CODE = 13  # SEG_IMEM


class SegmentFlags(IntEnum):
    """IDA segment flags definitions (can be combined)."""

    SFL_COMORG = 0x01  # IDP dependent field (IBM PC: if set, ORG directive is not commented out)
    SFL_OBOK = 0x02  # Orgbase is present? (IDP dependent field)
    SFL_COMORG_OBOK = 0x03  # COMORG + OBOK
    SFL_HIDDEN = 0x04  # Is the segment hidden?
    SFL_COMORG_HIDDEN = 0x05  # COMORG + HIDDEN
    SFL_OBOK_HIDDEN = 0x06  # OBOK + HIDDEN
    SFL_COMORG_OBOK_HIDDEN = 0x07  # COMORG + OBOK + HIDDEN
    SFL_DEBUG = 0x08  # Is the segment created for the debugger?
    SFL_COMORG_DEBUG = 0x09  # COMORG + DEBUG
    SFL_OBOK_DEBUG = 0x0A  # OBOK + DEBUG
    SFL_COMORG_OBOK_DEBUG = 0x0B  # COMORG + OBOK + DEBUG
    SFL_HIDDEN_DEBUG = 0x0C  # HIDDEN + DEBUG
    SFL_COMORG_HIDDEN_DEBUG = 0x0D  # COMORG + HIDDEN + DEBUG
    SFL_OBOK_HIDDEN_DEBUG = 0x0E  # OBOK + HIDDEN + DEBUG
    SFL_COMORG_OBOK_HIDDEN_DEBUG = 0x0F  # COMORG + OBOK + HIDDEN + DEBUG
    SFL_LOADER = 0x10  # Is the segment created by the loader?
    SFL_COMORG_LOADER = 0x11  # COMORG + LOADER
    SFL_OBOK_LOADER = 0x12  # OBOK + LOADER
    SFL_COMORG_OBOK_LOADER = 0x13  # COMORG + OBOK + LOADER
    SFL_HIDDEN_LOADER = 0x14  # HIDDEN + LOADER
    SFL_COMORG_HIDDEN_LOADER = 0x15  # COMORG + HIDDEN + LOADER
    SFL_OBOK_HIDDEN_LOADER = 0x16  # OBOK + HIDDEN + LOADER
    SFL_COMORG_OBOK_HIDDEN_LOADER = 0x17  # COMORG + OBOK + HIDDEN + LOADER
    SFL_DEBUG_LOADER = 0x18  # DEBUG + LOADER
    SFL_COMORG_DEBUG_LOADER = 0x19  # COMORG + DEBUG + LOADER
    SFL_OBOK_DEBUG_LOADER = 0x1A  # OBOK + DEBUG + LOADER
    SFL_COMORG_OBOK_DEBUG_LOADER = 0x1B  # COMORG + OBOK + DEBUG + LOADER
    SFL_HIDDEN_DEBUG_LOADER = 0x1C  # HIDDEN + DEBUG + LOADER
    SFL_COMORG_HIDDEN_DEBUG_LOADER = 0x1D  # COMORG + HIDDEN + DEBUG + LOADER
    SFL_OBOK_HIDDEN_DEBUG_LOADER = 0x1E  # OBOK + HIDDEN + DEBUG + LOADER
    SFL_COMORG_OBOK_HIDDEN_DEBUG_LOADER = 0x1F  # COMORG + OBOK + HIDDEN + DEBUG + LOADER
    SFL_HIDETYPE = 0x20  # Hide segment type (do not print it in the listing)
    SFL_COMORG_HIDETYPE = 0x21  # COMORG + HIDETYPE
    SFL_OBOK_HIDETYPE = 0x22  # OBOK + HIDETYPE
    SFL_COMORG_OBOK_HIDETYPE = 0x23  # COMORG + OBOK + HIDETYPE
    SFL_HIDDEN_HIDETYPE = 0x24  # HIDDEN + HIDETYPE
    SFL_COMORG_HIDDEN_HIDETYPE = 0x25  # COMORG + HIDDEN + HIDETYPE
    SFL_OBOK_HIDDEN_HIDETYPE = 0x26  # OBOK + HIDDEN + HIDETYPE
    SFL_COMORG_OBOK_HIDDEN_HIDETYPE = 0x27  # COMORG + OBOK + HIDDEN + HIDETYPE
    SFL_DEBUG_HIDETYPE = 0x28  # DEBUG + HIDETYPE
    SFL_COMORG_DEBUG_HIDETYPE = 0x29  # COMORG + DEBUG + HIDETYPE
    SFL_OBOK_DEBUG_HIDETYPE = 0x2A  # OBOK + DEBUG + HIDETYPE
    SFL_COMORG_OBOK_DEBUG_HIDETYPE = 0x2B  # COMORG + OBOK + DEBUG + HIDETYPE
    SFL_HIDDEN_DEBUG_HIDETYPE = 0x2C  # HIDDEN + DEBUG + HIDETYPE
    SFL_COMORG_HIDDEN_DEBUG_HIDETYPE = 0x2D  # COMORG + HIDDEN + DEBUG + HIDETYPE
    SFL_OBOK_HIDDEN_DEBUG_HIDETYPE = 0x2E  # OBOK + HIDDEN + DEBUG + HIDETYPE
    SFL_COMORG_OBOK_HIDDEN_DEBUG_HIDETYPE = 0x2F  # COMORG + OBOK + HIDDEN + DEBUG + HIDETYPE
    SFL_LOADER_HIDETYPE = 0x30  # LOADER + HIDETYPE
    SFL_COMORG_LOADER_HIDETYPE = 0x31  # COMORG + LOADER + HIDETYPE
    SFL_OBOK_LOADER_HIDETYPE = 0x32  # OBOK + LOADER + HIDETYPE
    SFL_COMORG_OBOK_LOADER_HIDETYPE = 0x33  # COMORG + OBOK + LOADER + HIDETYPE
    SFL_HIDDEN_LOADER_HIDETYPE = 0x34  # HIDDEN + LOADER + HIDETYPE
    SFL_COMORG_HIDDEN_LOADER_HIDETYPE = 0x35  # COMORG + HIDDEN + LOADER + HIDETYPE
    SFL_OBOK_HIDDEN_LOADER_HIDETYPE = 0x36  # OBOK + HIDDEN + LOADER + HIDETYPE
    SFL_COMORG_OBOK_HIDDEN_LOADER_HIDETYPE = 0x37  # COMORG + OBOK + HIDDEN + LOADER + HIDETYPE
    SFL_DEBUG_LOADER_HIDETYPE = 0x38  # DEBUG + LOADER + HIDETYPE
    SFL_COMORG_DEBUG_LOADER_HIDETYPE = 0x39  # COMORG + DEBUG + LOADER + HIDETYPE
    SFL_OBOK_DEBUG_LOADER_HIDETYPE = 0x3A  # OBOK + DEBUG + LOADER + HIDETYPE
    SFL_COMORG_OBOK_DEBUG_LOADER_HIDETYPE = 0x3B  # COMORG + OBOK + DEBUG + LOADER + HIDETYPE
    SFL_HIDDEN_DEBUG_LOADER_HIDETYPE = 0x3C  # HIDDEN + DEBUG + LOADER + HIDETYPE
    SFL_COMORG_HIDDEN_DEBUG_LOADER_HIDETYPE = 0x3D  # COMORG + HIDDEN + DEBUG + LOADER + HIDETYPE
    SFL_OBOK_HIDDEN_DEBUG_LOADER_HIDETYPE = 0x3E  # OBOK + HIDDEN + DEBUG + LOADER + HIDETYPE
    SFL_COMORG_OBOK_HIDDEN_DEBUG_LOADER_HIDETYPE = 0x3F  # COMORG + OBOK + HIDDEN + DEBUG + LOADER + HIDETYPE
    SFL_HEADER = 0x40  # Header segment (do not create offsets to it in the disassembly)
    SFL_COMORG_HEADER = 0x41  # COMORG + HEADER
    SFL_OBOK_HEADER = 0x42  # OBOK + HEADER
    SFL_COMORG_OBOK_HEADER = 0x43  # COMORG + OBOK + HEADER
    SFL_HIDDEN_HEADER = 0x44  # HIDDEN + HEADER
    SFL_COMORG_HIDDEN_HEADER = 0x45  # COMORG + HIDDEN + HEADER
    SFL_OBOK_HIDDEN_HEADER = 0x46  # OBOK + HIDDEN + HEADER
    SFL_COMORG_OBOK_HIDDEN_HEADER = 0x47  # COMORG + OBOK + HIDDEN + HEADER
    SFL_DEBUG_HEADER = 0x48  # DEBUG + HEADER
    SFL_COMORG_DEBUG_HEADER = 0x49  # COMORG + DEBUG + HEADER
    SFL_OBOK_DEBUG_HEADER = 0x4A  # OBOK + DEBUG + HEADER
    SFL_COMORG_OBOK_DEBUG_HEADER = 0x4B  # COMORG + OBOK + DEBUG + HEADER
    SFL_HIDDEN_DEBUG_HEADER = 0x4C  # HIDDEN + DEBUG + HEADER
    SFL_COMORG_HIDDEN_DEBUG_HEADER = 0x4D  # COMORG + HIDDEN + DEBUG + HEADER
    SFL_OBOK_HIDDEN_DEBUG_HEADER = 0x4E  # OBOK + HIDDEN + DEBUG + HEADER
    SFL_COMORG_OBOK_HIDDEN_DEBUG_HEADER = 0x4F  # COMORG + OBOK + HIDDEN + DEBUG + HEADER
    SFL_LOADER_HEADER = 0x50  # LOADER + HEADER
    SFL_COMORG_LOADER_HEADER = 0x51  # COMORG + LOADER + HEADER
    SFL_OBOK_LOADER_HEADER = 0x52  # OBOK + LOADER + HEADER
    SFL_COMORG_OBOK_LOADER_HEADER = 0x53  # COMORG + OBOK + LOADER + HEADER
    SFL_HIDDEN_LOADER_HEADER = 0x54  # HIDDEN + LOADER + HEADER
    SFL_COMORG_HIDDEN_LOADER_HEADER = 0x55  # COMORG + HIDDEN + LOADER + HEADER
    SFL_OBOK_HIDDEN_LOADER_HEADER = 0x56  # OBOK + HIDDEN + LOADER + HEADER
    SFL_COMORG_OBOK_HIDDEN_LOADER_HEADER = 0x57  # COMORG + OBOK + HIDDEN + LOADER + HEADER
    SFL_DEBUG_LOADER_HEADER = 0x58  # DEBUG + LOADER + HEADER
    SFL_COMORG_DEBUG_LOADER_HEADER = 0x59  # COMORG + DEBUG + LOADER + HEADER
    SFL_OBOK_DEBUG_LOADER_HEADER = 0x5A  # OBOK + DEBUG + LOADER + HEADER
    SFL_COMORG_OBOK_DEBUG_LOADER_HEADER = 0x5B  # COMORG + OBOK + DEBUG + LOADER + HEADER
    SFL_HIDDEN_DEBUG_LOADER_HEADER = 0x5C  # HIDDEN + DEBUG + LOADER + HEADER
    SFL_COMORG_HIDDEN_DEBUG_LOADER_HEADER = 0x5D  # COMORG + HIDDEN + DEBUG + LOADER + HEADER
    SFL_OBOK_HIDDEN_DEBUG_LOADER_HEADER = 0x5E  # OBOK + HIDDEN + DEBUG + LOADER + HEADER
    SFL_COMORG_OBOK_HIDDEN_DEBUG_LOADER_HEADER = 0x5F  # COMORG + OBOK + HIDDEN + DEBUG + LOADER + HEADER
    SFL_HIDETYPE_HEADER = 0x60  # HIDETYPE + HEADER
    SFL_COMORG_HIDETYPE_HEADER = 0x61  # COMORG + HIDETYPE + HEADER
    SFL_OBOK_HIDETYPE_HEADER = 0x62  # OBOK + HIDETYPE + HEADER
    SFL_COMORG_OBOK_HIDETYPE_HEADER = 0x63  # COMORG + OBOK + HIDETYPE + HEADER
    SFL_HIDDEN_HIDETYPE_HEADER = 0x64  # HIDDEN + HIDETYPE + HEADER
    SFL_COMORG_HIDDEN_HIDETYPE_HEADER = 0x65  # COMORG + HIDDEN + HIDETYPE + HEADER
    SFL_OBOK_HIDDEN_HIDETYPE_HEADER = 0x66  # OBOK + HIDDEN + HIDETYPE + HEADER
    SFL_COMORG_OBOK_HIDDEN_HIDETYPE_HEADER = 0x67  # COMORG + OBOK + HIDDEN + HIDETYPE + HEADER
    SFL_DEBUG_HIDETYPE_HEADER = 0x68  # DEBUG + HIDETYPE + HEADER
    SFL_COMORG_DEBUG_HIDETYPE_HEADER = 0x69  # COMORG + DEBUG + HIDETYPE + HEADER
    SFL_OBOK_DEBUG_HIDETYPE_HEADER = 0x6A  # OBOK + DEBUG + HIDETYPE + HEADER
    SFL_COMORG_OBOK_DEBUG_HIDETYPE_HEADER = 0x6B  # COMORG + OBOK + DEBUG + HIDETYPE + HEADER
    SFL_HIDDEN_DEBUG_HIDETYPE_HEADER = 0x6C  # HIDDEN + DEBUG + HIDETYPE + HEADER
    SFL_COMORG_HIDDEN_DEBUG_HIDETYPE_HEADER = 0x6D  # COMORG + HIDDEN + DEBUG + HIDETYPE + HEADER
    SFL_OBOK_HIDDEN_DEBUG_HIDETYPE_HEADER = 0x6E  # OBOK + HIDDEN + DEBUG + HIDETYPE + HEADER
    SFL_COMORG_OBOK_HIDDEN_DEBUG_HIDETYPE_HEADER = 0x6F  # COMORG + OBOK + HIDDEN + DEBUG + HIDETYPE + HEADER
    SFL_LOADER_HIDETYPE_HEADER = 0x70  # LOADER + HIDETYPE + HEADER
    SFL_COMORG_LOADER_HIDETYPE_HEADER = 0x71  # COMORG + LOADER + HIDETYPE + HEADER
    SFL_OBOK_LOADER_HIDETYPE_HEADER = 0x72  # OBOK + LOADER + HIDETYPE + HEADER
    SFL_COMORG_OBOK_LOADER_HIDETYPE_HEADER = 0x73  # COMORG + OBOK + LOADER + HIDETYPE + HEADER
    SFL_HIDDEN_LOADER_HIDETYPE_HEADER = 0x74  # HIDDEN + LOADER + HIDETYPE + HEADER
    SFL_COMORG_HIDDEN_LOADER_HIDETYPE_HEADER = 0x75  # COMORG + HIDDEN + LOADER + HIDETYPE + HEADER
    SFL_OBOK_HIDDEN_LOADER_HIDETYPE_HEADER = 0x76  # OBOK + HIDDEN + LOADER + HIDETYPE + HEADER
    SFL_COMORG_OBOK_HIDDEN_LOADER_HIDETYPE_HEADER = 0x77  # COMORG + OBOK + HIDDEN + LOADER + HIDETYPE + HEADER
    SFL_DEBUG_LOADER_HIDETYPE_HEADER = 0x78  # DEBUG + LOADER + HIDETYPE + HEADER
    SFL_COMORG_DEBUG_LOADER_HIDETYPE_HEADER = 0x79  # COMORG + DEBUG + LOADER + HIDETYPE + HEADER
    SFL_OBOK_DEBUG_LOADER_HIDETYPE_HEADER = 0x7A  # OBOK + DEBUG + LOADER + HIDETYPE + HEADER
    SFL_COMORG_OBOK_DEBUG_LOADER_HIDETYPE_HEADER = 0x7B  # COMORG + OBOK + DEBUG + LOADER + HIDETYPE + HEADER
    SFL_HIDDEN_DEBUG_LOADER_HIDETYPE_HEADER = 0x7C  # HIDDEN + DEBUG + LOADER + HIDETYPE + HEADER
    SFL_COMORG_HIDDEN_DEBUG_LOADER_HIDETYPE_HEADER = 0x7D  # COMORG + HIDDEN + DEBUG + LOADER + HIDETYPE + HEADER
    SFL_OBOK_HIDDEN_DEBUG_LOADER_HIDETYPE_HEADER = 0x7E  # OBOK + HIDDEN + DEBUG + LOADER + HIDETYPE + HEADER
    SFL_ALL = 0x7F  # All flags combined


class SegmentPermissions(IntEnum):
    """IDA segment permissions definitions (can be combined)."""

    SEGPERM_UNKNOWN = 0  # Unknown
    SEGPERM_EXEC = 1  # Execute
    SEGPERM_WRITE = 2  # Write
    SEGPERM_EXEC_WRITE = 3  # Execute + Write
    SEGPERM_READ = 4  # Read
    SEGPERM_EXEC_READ = 5  # Execute + Read
    SEGPERM_READ_WRITE = 6  # Read + Write
    SEGPERM_MAXVAL = 7  # Execute + Write + Read


class CustomModifier(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t) -> None:
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, local_variables) -> bool:
        for local_variables_saved in local_variables.lvvec:
            local_variables_saved: ida_hexrays.lvar_saved_info_t
            if local_variables_saved.name == self.var_name:
                local_variables_saved.type = self.new_type
                return True
        return False


class HexEA(str):
    __slots__ = ()
    """Hex string that always starts with 0x and exposes `ea_t` (int) property."""

    def __new__(cls, value: str | int | ea_t) -> "HexEA":
        if isinstance(value, int):
            value = f"0x{value:x}"
        elif isinstance(value, str):
            s = value.strip()
            value = f"0x{s}" if not s.lower().startswith("0x") else s
        else:
            msg = "Value must be str or int"
            raise TypeError(msg)
        return super().__new__(cls, value)

    @property
    def ea_t(self) -> ea_t:
        s = self.strip()
        return ea_t(int(s, 16))

    @classmethod
    def __get_pydantic_core_schema__(cls, _source, _handler):
        def _validate(v: str | int | ea_t) -> "HexEA":
            return cls(v)

        return cs.no_info_after_validator_function(_validate, cs.str_schema())

    def __repr__(self) -> str:
        return f"{self}"


class NameData(BaseModel):
    address: HexEA
    name: str

    @classmethod
    def from_tuple(cls, data: tuple[ea_t | HexEA, str]) -> "NameData":
        address = data[0]
        name = data[1]
        if address is None:
            msg = "No address found in name tuple"
            raise OperationError(msg)
        address = HexEA(address)
        if name is None:
            name = f"unk_{address}"
        return cls(address=HexEA(data[0]), name=name)


class SegmentData(BaseModel):
    start_ea: HexEA
    end_ea: HexEA
    name: str
    type: str
    flags: str
    permissions: str

    @classmethod
    def from_segment_t(cls, segment: segment_t, name: str) -> "SegmentData":
        return cls(
            start_ea=HexEA(segment.start_ea),
            end_ea=HexEA(segment.end_ea),
            name=name,
            type=SegmentType(segment.type).name,
            flags=SegmentFlags(segment.flags).name,
            permissions=SegmentPermissions(segment.perm).name,
        )


class ForwarderInfo(BaseModel):
    ordinal: int
    name: str


class FunctionData(BaseModel):
    start_ea: HexEA
    end_ea: HexEA
    name: str = "Unknown"

    @classmethod
    def from_func_t(cls, func: func_t) -> "FunctionData | None":
        if not func:
            return None
        if not func.name:
            return cls(start_ea=HexEA(func.start_ea), end_ea=HexEA(func.end_ea))
        return cls(start_ea=HexEA(func.start_ea), end_ea=HexEA(func.end_ea), name=func.name)


class EntryData(BaseModel):
    ordinal: int
    address: HexEA
    name: str
    forwarder_name: str | None

    @classmethod
    def from_ida(cls, entry: EntryInfo | None) -> "EntryData":
        if entry is None:
            msg = "Entry not found"
            raise OperationError(msg)
        return EntryData(
            ordinal=entry.ordinal,
            address=HexEA(entry.address),
            forwarder_name=entry.forwarder_name,
            name=entry.name,
        )


class StringData(BaseModel):
    address: HexEA
    length: int
    type: str
    contents: bytes

    @classmethod
    def from_ida(cls, item: StringItem) -> "StringData":
        return cls(address=HexEA(item.address), length=item.length, type=str(item.type.name), contents=item.contents)


class XrefData(BaseModel):
    from_ea: HexEA
    to_ea: HexEA
    type: str
    is_code: bool
    user_defined: bool
    is_flow: bool

    @classmethod
    def from_ida(cls, xref: XrefInfo) -> "XrefData":
        return cls(
            from_ea=HexEA(xref.from_ea),
            to_ea=HexEA(xref.to_ea),
            type=xref.type.name,
            is_code=xref.is_code,
            user_defined=xref.user,
            is_flow=xref.is_flow,
        )


class CommentData(BaseModel):
    ea: HexEA
    comment: str
    repeatable: bool

    @classmethod
    def from_ida(cls, comment: CommentInfo) -> "CommentData":
        return cls(ea=HexEA(comment.ea), comment=comment.comment, repeatable=comment.repeatable)
