import re
import struct

VERSION = 1
MAGIC_LENGTH = 8
HEADER_LENGTH = MAGIC_LENGTH + 4
NAME = re.compile(r"[A-Z0-9_]+")


class FixtureFormatError(Exception):
    pass


def pack(magic, vectors):
    records = {}
    for name, payload in vectors:
        if not NAME.fullmatch(name):
            raise FixtureFormatError(
                f"{name}: names are upper-case ASCII, digits and underscores"
            )
        if len(name) > 0xFF:
            raise FixtureFormatError(f"{name}: the name does not fit a single length byte")
        if len(payload) % 2:
            raise FixtureFormatError(f"{name}: an odd number of hex digits")
        if name in records:
            raise FixtureFormatError(f"{name}: duplicate vector")
        try:
            records[name] = bytes.fromhex(payload)
        except ValueError as error:
            raise FixtureFormatError(f"{name}: {error}") from None

    out = bytearray(magic)
    out += struct.pack(">HH", VERSION, len(records))
    for name in sorted(records):
        payload = records[name]
        out.append(len(name))
        out += name.encode("ascii")
        out += struct.pack(">I", len(payload))
        out += payload
    return bytes(out)


def unpack(magic, blob):
    return tuple(_unpack(magic, blob))


def _unpack(magic, blob):
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise FixtureFormatError("a fixture is a byte string")
    blob = bytes(blob)
    if not blob:
        raise FixtureFormatError("the fixture is empty")
    if len(blob) < MAGIC_LENGTH:
        raise FixtureFormatError(
            f"the fixture is {len(blob)} bytes, shorter than the {MAGIC_LENGTH}-byte magic"
        )
    if blob[:MAGIC_LENGTH] != magic:
        raise FixtureFormatError(f"bad magic: expected {magic.decode('ascii', 'replace')}")
    if len(blob) < HEADER_LENGTH:
        raise FixtureFormatError("the fixture header is truncated")
    version, count = struct.unpack_from(">HH", blob, MAGIC_LENGTH)
    if version != VERSION:
        raise FixtureFormatError(f"unsupported format version {version}")
    at = HEADER_LENGTH
    previous = None
    seen = set()
    for index in range(count):
        if at >= len(blob):
            raise FixtureFormatError(
                f"record {index}: the fixture ends before its name length"
            )
        name_length = blob[at]
        at += 1
        if name_length == 0:
            raise FixtureFormatError(f"record {index}: an empty record name")
        if at + name_length > len(blob):
            raise FixtureFormatError(f"record {index}: the record name is truncated")
        raw_name = blob[at : at + name_length]
        at += name_length
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            raise FixtureFormatError(f"record {index}: a non-ASCII record name") from None
        if not NAME.fullmatch(name):
            raise FixtureFormatError(f"{name}: not an upper-case ASCII record name")
        if name in seen:
            raise FixtureFormatError(f"{name}: duplicate record name")
        if previous is not None and name <= previous:
            raise FixtureFormatError(f"{previous} then {name} is not sorted")
        seen.add(name)
        previous = name
        if at + 4 > len(blob):
            raise FixtureFormatError(f"{name}: the payload length is truncated")
        (payload_length,) = struct.unpack_from(">I", blob, at)
        at += 4
        if at + payload_length > len(blob):
            raise FixtureFormatError(
                f"{name}: the payload claims {payload_length} bytes, "
                f"{len(blob) - at} remain"
            )
        yield name, blob[at : at + payload_length].hex()
        at += payload_length
    if at != len(blob):
        raise FixtureFormatError(f"{len(blob) - at} trailing bytes")


def read_listing(text):
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise FixtureFormatError(f"line {number}: expected 'NAME <hex>'")
        yield parts[0], parts[1]
