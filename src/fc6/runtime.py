"""Read-only identification and session sampling of a running FC6 process."""

import hashlib
import struct
from collections.abc import Callable, Mapping
from pathlib import Path

from fc6.build import IMAGE_SIZE
from fc6.storm_peers import SESSION_STORM_MAX_PEERS_ID_OFFSET, SESSION_STORM_MAX_PEERS_OFFSET
from fc6.variants import VARIANTS, Variant


SESSION_MANAGER_RVA = 0x6B68D80
SESSION_VTABLE_RVA = 0x58E8A08
SESSION_TABLE_OFFSETS = (("primary", 0xC8), ("secondary", 0x110))
MAX_DIAGNOSTIC_SESSIONS = 256
SESSION_SNAPSHOT_SIZE = 0x4B0
SLOTS_OFFSET = 0x3E0
DESCRIPTOR_CAPACITY_OFFSET = 0x439
SESSION_ID_OFFSET = 0x4AC
# Original code that every variant keeps: the descriptor capacity getter and the
# OnJoinRequest free-slot check. They prove the field offsets read below.
CODE_PROBES = {
    0xD1EDA7: bytes.fromhex("0fb68039040000"),
    0xD4274A: bytes.fromhex("410fb687e2030000412a87e1030000412a87e00300003c010f8354020000"),
}

MemoryReader = Callable[[int, int], bytes]


def read_exact(reader: MemoryReader, address: int, size: int) -> bytes:
    if address <= 0:
        raise RuntimeError(f"Cannot read null or invalid address {address:#x}")
    data = reader(address, size)
    if len(data) != size:
        raise RuntimeError(f"Cannot read {size} bytes at {address:#x}")
    return data


def describe_session(data: bytes) -> dict:
    filled, reserved, maximum = data[SLOTS_OFFSET:SLOTS_OFFSET + 3]
    descriptor_maximum, team_count = data[DESCRIPTOR_CAPACITY_OFFSET:DESCRIPTOR_CAPACITY_OFFSET + 2]
    storm_max_peers = struct.unpack_from("<I", data, SESSION_STORM_MAX_PEERS_OFFSET)[0]
    storm_max_peers_id = struct.unpack_from("<I", data, SESSION_STORM_MAX_PEERS_ID_OFFSET)[0]
    available = maximum - reserved - filled
    return {
        "filled_slots": filled,
        "reserved_slots": reserved,
        "max_slots": maximum,
        "available_slots": available,
        "descriptor_max_players": descriptor_maximum,
        "team_record_count": team_count,
        "storm_max_peers": storm_max_peers,
        "storm_max_peers_id": storm_max_peers_id,
        "consistent": maximum == descriptor_maximum and available >= 0,
        # The peer-to-peer layer rejects joins beyond maxPeers without a game-level reason
        "storm_allows_max_slots": storm_max_peers >= maximum,
    }


def sample_sessions(reader: MemoryReader, module_base: int) -> dict:
    global_address = module_base + SESSION_MANAGER_RVA
    manager_bytes = read_exact(reader, global_address, 8)
    manager = struct.unpack("<Q", manager_bytes)[0]
    result = {"manager_initialized": bool(manager), "sessions": []}
    if not manager:
        return result

    for table_name, offset in SESSION_TABLE_OFFSETS:
        header_address = manager + offset
        header = read_exact(reader, header_address, 16)
        table, metadata = struct.unpack("<QQ", header)
        count = (metadata >> 32) & 0x7FFFFFFF
        if count > MAX_DIAGNOSTIC_SESSIONS:
            raise RuntimeError(f"Session count {count} exceeds diagnostic limit")
        if count and not table:
            raise RuntimeError("Nonempty session collection has a null table")
        entries = read_exact(reader, table, count * 16) if count else b""
        for session_id, _, address in struct.iter_unpack("<IIQ", entries):
            data = read_exact(reader, address, SESSION_SNAPSHOT_SIZE)
            vtable = struct.unpack_from("<Q", data)[0]
            if vtable != module_base + SESSION_VTABLE_RVA:
                raise RuntimeError(f"Unexpected session vtable at {address:#x}")
            if struct.unpack_from("<I", data, SESSION_ID_OFFSET)[0] != session_id:
                raise RuntimeError(f"Changed or unexpected session ID at {address:#x}")
            result["sessions"].append({
                "session_id": session_id, "table": table_name, "address": hex(address),
                **describe_session(data),
            })
        if read_exact(reader, header_address, 16) != header:
            raise RuntimeError("Session collection changed during observation, sample again")
        if count and read_exact(reader, table, len(entries)) != entries:
            raise RuntimeError("Session pointers changed during observation, sample again")

    if read_exact(reader, global_address, 8) != manager_bytes:
        raise RuntimeError("Session manager changed during observation, sample again")
    return result


def verify_module(reader: MemoryReader, base: int, size: int, path: Path,
                  variants: Mapping[str, Variant] = VARIANTS) -> Variant:
    """Accept only a known file hash whose variant-specific code is present in memory."""
    if size != IMAGE_SIZE:
        raise RuntimeError(f"Unsupported loaded module size {size:#x}")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    variant = next((item for item in variants.values() if item.sha256 == digest), None)
    if variant is None:
        raise RuntimeError(f"Unsupported DLL SHA-256 {digest}")
    for rva, expected in (CODE_PROBES | variant.probes()).items():
        if read_exact(reader, base + rva, len(expected)) != expected:
            raise RuntimeError(f"Loaded code of variant {variant.name} differs at RVA {rva:#x}")
    return variant
