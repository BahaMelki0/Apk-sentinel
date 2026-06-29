from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass

ANDROID_NS = "http://schemas.android.com/apk/res/android"

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_FIRST_COLOR_INT = 0x1C
TYPE_LAST_COLOR_INT = 0x1F

UTF8_FLAG = 0x00000100
NO_INDEX = 0xFFFFFFFF


class AxmlParseError(ValueError):
    """Raised when Android binary XML cannot be parsed."""


@dataclass
class _Chunk:
    kind: int
    header_size: int
    size: int


def parse_xml_bytes(data: bytes) -> ET.Element:
    """Parse plaintext XML or Android compiled binary XML into ElementTree."""
    if data.lstrip().startswith(b"<"):
        try:
            return ET.fromstring(data)
        except ET.ParseError as exc:
            raise AxmlParseError(str(exc)) from exc
    return _BinaryXmlParser(data).parse()


class _BinaryXmlParser:
    def __init__(self, data: bytes):
        self.data = data
        self.strings: list[str] = []
        self.namespaces: dict[int, str] = {}

    def parse(self) -> ET.Element:
        root_chunk = self._read_chunk(0)
        if root_chunk.kind != RES_XML_TYPE:
            raise AxmlParseError("not an Android binary XML document")

        offset = root_chunk.header_size
        stack: list[ET.Element] = []
        root: ET.Element | None = None

        while offset < root_chunk.size:
            chunk = self._read_chunk(offset)
            if chunk.kind == RES_STRING_POOL_TYPE:
                self.strings = self._read_string_pool(offset, chunk)
            elif chunk.kind == RES_XML_START_NAMESPACE_TYPE:
                prefix_idx, uri_idx = self._read_namespace(offset)
                if prefix_idx != NO_INDEX and uri_idx != NO_INDEX:
                    self.namespaces[uri_idx] = self._string(uri_idx)
            elif chunk.kind == RES_XML_END_NAMESPACE_TYPE:
                pass
            elif chunk.kind == RES_XML_START_ELEMENT_TYPE:
                element = self._read_start_element(offset)
                if stack:
                    stack[-1].append(element)
                else:
                    root = element
                stack.append(element)
            elif chunk.kind == RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()
            offset += chunk.size

        if root is None:
            raise AxmlParseError("document does not contain a root element")
        return root

    def _read_chunk(self, offset: int) -> _Chunk:
        if offset + 8 > len(self.data):
            raise AxmlParseError("truncated chunk header")
        kind, header_size, size = struct.unpack_from("<HHI", self.data, offset)
        if size <= 0 or offset + size > len(self.data):
            raise AxmlParseError(f"invalid chunk size at offset {offset}")
        return _Chunk(kind=kind, header_size=header_size, size=size)

    def _read_string_pool(self, offset: int, chunk: _Chunk) -> list[str]:
        if chunk.header_size < 28:
            raise AxmlParseError("invalid string pool header")
        string_count, style_count, flags, strings_start, _styles_start = struct.unpack_from(
            "<IIIII", self.data, offset + 8
        )
        offsets_start = offset + chunk.header_size
        strings_base = offset + strings_start
        strings: list[str] = []
        is_utf8 = bool(flags & UTF8_FLAG)

        for index in range(string_count):
            string_offset = struct.unpack_from("<I", self.data, offsets_start + index * 4)[0]
            absolute = strings_base + string_offset
            strings.append(self._read_utf8(absolute) if is_utf8 else self._read_utf16(absolute))

        # style_count is intentionally ignored; styles are not needed for manifest analysis.
        _ = style_count
        return strings

    def _read_utf8(self, offset: int) -> str:
        _, offset = self._read_length8(offset)
        byte_length, offset = self._read_length8(offset)
        raw = self.data[offset : offset + byte_length]
        return raw.decode("utf-8", errors="replace")

    def _read_utf16(self, offset: int) -> str:
        length, offset = self._read_length16(offset)
        raw = self.data[offset : offset + length * 2]
        return raw.decode("utf-16le", errors="replace")

    def _read_length8(self, offset: int) -> tuple[int, int]:
        first = self.data[offset]
        offset += 1
        if first & 0x80:
            second = self.data[offset]
            offset += 1
            return ((first & 0x7F) << 8) | second, offset
        return first, offset

    def _read_length16(self, offset: int) -> tuple[int, int]:
        first = struct.unpack_from("<H", self.data, offset)[0]
        offset += 2
        if first & 0x8000:
            second = struct.unpack_from("<H", self.data, offset)[0]
            offset += 2
            return ((first & 0x7FFF) << 16) | second, offset
        return first, offset

    def _read_namespace(self, offset: int) -> tuple[int, int]:
        # Chunk header + line number + comment + prefix + uri.
        return struct.unpack_from("<II", self.data, offset + 16)

    def _read_start_element(self, offset: int) -> ET.Element:
        ns_idx, name_idx, attr_start, attr_size, attr_count, _id_idx, _class_idx, _style_idx = struct.unpack_from(
            "<IIHHHHHH", self.data, offset + 16
        )
        tag = self._qualified_name(ns_idx, name_idx)
        element = ET.Element(tag)
        # attributeStart is relative to the ResXMLTree_attrExt structure, which
        # begins after the 16-byte ResXMLTree_node header.
        attrs_offset = offset + 16 + attr_start

        for index in range(attr_count):
            attr_offset = attrs_offset + index * attr_size
            attr_ns, attr_name, raw_value, value_size, _res0, value_type, value_data = struct.unpack_from(
                "<IIIHBBI", self.data, attr_offset
            )
            _ = value_size
            key = self._qualified_name(attr_ns, attr_name, attribute=True)
            element.attrib[key] = self._value(raw_value, value_type, value_data)

        return element

    def _qualified_name(self, ns_idx: int, name_idx: int, attribute: bool = False) -> str:
        name = self._string(name_idx)
        if ns_idx == NO_INDEX:
            return name
        namespace = self._string(ns_idx)
        if namespace == ANDROID_NS and attribute:
            return f"android:{name}"
        return f"{{{namespace}}}{name}"

    def _value(self, raw_value: int, value_type: int, value_data: int) -> str:
        if raw_value != NO_INDEX:
            return self._string(raw_value)
        if value_type == TYPE_STRING:
            return self._string(value_data)
        if value_type == TYPE_INT_BOOLEAN:
            return "true" if value_data else "false"
        if value_type == TYPE_INT_DEC:
            return str(_signed32(value_data))
        if value_type == TYPE_INT_HEX:
            return f"0x{value_data:08x}"
        if value_type == TYPE_REFERENCE:
            return f"@0x{value_data:08x}"
        if value_type == TYPE_ATTRIBUTE:
            return f"?0x{value_data:08x}"
        if value_type == TYPE_FLOAT:
            return str(struct.unpack("<f", struct.pack("<I", value_data))[0])
        if TYPE_FIRST_COLOR_INT <= value_type <= TYPE_LAST_COLOR_INT:
            return f"#{value_data:08x}"
        if value_type == TYPE_NULL:
            return ""
        return f"0x{value_data:08x}"

    def _string(self, index: int) -> str:
        if index == NO_INDEX:
            return ""
        try:
            return self.strings[index]
        except IndexError as exc:
            raise AxmlParseError(f"string index out of range: {index}") from exc


def _signed32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value
