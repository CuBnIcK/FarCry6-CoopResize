"""Bounded read-only join-state recorder.

Samples omit raw addresses, session IDs and GUIDs, and never follow message-string
pointers, so the JSONL output contains no account, invitation or network data.
"""

import datetime as dt
import struct
import time
from collections.abc import Callable, Iterator

from fc6.runtime import SESSION_MANAGER_RVA, MemoryReader, read_exact, sample_sessions


PLATFORM_GLOBAL_RVA = 0x6E0B010
PLATFORM_INTERFACE_RVA = 0x5AEF370
MODE_ROOT_RVA = 0x6A5EA60
SERVICE_CONTAINER_RVA = 0x6B6C610
SESSION_LEAVE_RESULT_OFFSET = 0x3B0
MAX_COLLECTION_SIZE = 256
# Gameplay layer. CFCXCoopService answers a joining client's initial mission-block request
# only when its ready flag is set and CPlayerService has a player object for that peer.
PLAYER_SERVICE_RVA = 0x6C04A80
PLAYER_SERVICE_VTABLE_RVA = 0x5AC4B10
PLAYER_VTABLE_RVA = 0x5AE4788
COOP_SERVICE_RVA = 0x6C04AB8
COOP_SERVICE_VTABLE_RVA = 0x5AC55F0
COOP_MBLOCK_READY_OFFSETS = (0x1D0, 0x40)  # pointer in the service, then a bool in that object
# Set to 2 by HandleMasterToReplica_MBlockStatesBuffer once a client has every chunk of the host's reply
COOP_MBLOCK_SYNC_STATE_OFFSET = 0xD0
GAME_MODE_PLAYER_OFFSET = 0x20
WORLD_STATE_OFFSETS = (0xA8, 0x44)  # CPlayableGameModePlayer pointer, then IsWorldLoaded
# CPlayerService::GetPlayerFromPeerId maps a peer through the members of the session whose ID
# is at session manager +0x128, then matches the member object against CPlayer +0x18.
GAME_SESSION_ID_OFFSET = 0x128
SESSION_MEMBERS_OFFSET = 0x378
MEMBER_PEER_TREE_OFFSET = 0x20  # std::map<session id, peer info>, root at +0x10 of the header
PLAYER_MEMBER_OFFSET = 0x18
MAX_TREE_DEPTH = 64
# Names from the DLL's own result-code lookup tables
RESULT_NAMES = {
    0x1E2AEC01: "INTERNAL_LEAVE_REASON_UNDEFINED",
    0x214C8F5A: "INTERNAL_JOIN_HOST_NOT_READY",
    0x3D0B2D62: "INTERNAL_ERROR_INVITATION_NO_ACTIVE_SESSION",
    0x4D82D34C: "SESSIONS_SESSIONLIMITEXCEEDED",
    0x8BC0445B: "INTERNAL_ERROR_SESSION_JOIN_FAILED_TEAM_FULL",
    0xA34F0AA0: "INTERNAL_ERROR_SESSION_JOIN_FAILED_OUTDATED_TEAM_REVISION",
    0xDE2125EF: "ECHO_LEAVE_REASON_CONNECTION_REACH_FAILED",
    0xE26CD333: "INTERNAL_SESSION_OFFLINE",
    0xE4691238: "INTERNAL_ERROR_SESSION_JOIN_FAILED_SESSION_FULL",
}
SERVICE_NAMES = {
    0x58E0D08: "CMatchmakingService",
    0x58EA298: "CFleetNotificationService",
    0x58E0998: "CGameConfigService",
    0x58E1190: "CReputationService",
    0x58E1E90: "CSessionsService",
    0x58FB670: "CFriendsService",
    0x58DF8B0: "CClientMetricsService",
    0x58EAB58: "CSecondaryStoreService",
    0x58FAD78: "CClubService",
    0x58E6790: "CLeaderboardService",
}
SERVICE_STATUSES = {0: "starting", 1: "started", 2: "stopping", 3: "stopped"}
SLOT_FIELDS = (
    "table", "filled_slots", "reserved_slots", "max_slots", "available_slots",
    "descriptor_max_players", "team_record_count", "storm_max_peers", "storm_max_peers_id",
    "consistent", "storm_allows_max_slots",
)


def read_pointer(reader: MemoryReader, address: int) -> int:
    return struct.unpack("<Q", read_exact(reader, address, 8))[0]


def read_result(reader: MemoryReader, address: int) -> dict:
    # CResult: category byte, code, then a nested category and origin. Strings are skipped.
    fields = ((0, 1), (4, 4), (0x28, 1), (0x2C, 4))
    values = [read_exact(reader, address + offset, size) for offset, size in fields]
    if values != [read_exact(reader, address + offset, size) for offset, size in fields]:
        raise RuntimeError("Result changed during observation")
    code = int.from_bytes(values[1], "little")
    return {
        "category": values[0][0], "code": hex(code),
        "name": RESULT_NAMES.get(code, "unknown"),
        "secondary_category": values[2][0],
        "origin": hex(int.from_bytes(values[3], "little")),
    }


def read_pointer_array(reader: MemoryReader, address: int) -> tuple[int, ...]:
    header = read_exact(reader, address, 16)
    pointer, metadata = struct.unpack("<QQ", header)
    count = (metadata >> 32) & 0x7FFFFFFF
    if count > MAX_COLLECTION_SIZE:
        raise RuntimeError("Pointer collection limit exceeded")
    if count and not pointer:
        raise RuntimeError("Nonempty pointer collection has a null table")
    data = read_exact(reader, pointer, count * 8) if count else b""
    if read_exact(reader, address, 16) != header:
        raise RuntimeError("Pointer collection changed")
    if count and read_exact(reader, pointer, len(data)) != data:
        raise RuntimeError("Pointer entries changed")
    return tuple(value[0] for value in struct.iter_unpack("<Q", data))


def sample_network(reader: MemoryReader, base: int) -> dict:
    snapshot = sample_sessions(reader, base)
    sessions = []
    for session in snapshot["sessions"]:
        item = {key: session[key] for key in SLOT_FIELDS}
        item["stored_leave_result"] = read_result(
            reader, int(session["address"], 16) + SESSION_LEAVE_RESULT_OFFSET
        )
        sessions.append(item)
    return {"manager_initialized": snapshot["manager_initialized"], "sessions": sessions}


def sample_platform(reader: MemoryReader, base: int) -> dict:
    address = read_pointer(reader, base + PLATFORM_GLOBAL_RVA)
    if not address:
        return {"initialized": False}
    if read_pointer(reader, address + 0x10) != base + PLATFORM_INTERFACE_RVA:
        raise RuntimeError("Unexpected platform interface")
    result = {
        "initialized": True,
        "mode_id": hex(int.from_bytes(read_exact(reader, address + 0x88, 4), "little")),
        "session_present": any(read_exact(reader, address + 0xD0, 16)),
        "stored_result": read_result(reader, address + 0x38),
    }
    if read_pointer(reader, base + PLATFORM_GLOBAL_RVA) != address:
        raise RuntimeError("Platform service changed")
    return result


def sample_mode(reader: MemoryReader, base: int) -> dict:
    root = read_pointer(reader, base + MODE_ROOT_RVA)
    mode = read_pointer(reader, root + 0x90) if root else 0
    session = read_pointer(reader, mode + 0x110) if mode else 0
    if not session:
        return {"initialized": False}
    counts = read_exact(reader, session + 0xC8, 3)
    result = {
        "initialized": True,
        "mode_id": hex(int.from_bytes(read_exact(reader, session + 0xA8, 4), "little")),
        "min_team_size": counts[0], "max_team_size": counts[1],
        "number_of_teams": counts[2],
    }
    if (read_pointer(reader, base + MODE_ROOT_RVA) != root
            or read_pointer(reader, root + 0x90) != mode
            or read_pointer(reader, mode + 0x110) != session):
        raise RuntimeError("Mode session changed")
    return result


def sample_services(reader: MemoryReader, base: int) -> dict:
    container = read_pointer(reader, base + SERVICE_CONTAINER_RVA)
    registry = read_pointer(reader, container + 0x30) if container else 0
    if not registry:
        return {"initialized": False, "services": []}
    services = {}
    entries = 0
    for node in read_pointer_array(reader, registry + 0x10):
        addresses = read_pointer_array(reader, node + 0x18)
        entries += len(addresses)
        if entries > MAX_COLLECTION_SIZE:
            raise RuntimeError("Service collection limit exceeded")
        for address in addresses:
            vtable = read_pointer(reader, address)
            name = SERVICE_NAMES.get(vtable - base)
            if name is None:
                continue
            status = int.from_bytes(read_exact(reader, address + 0x20, 4), "little")
            services[address] = {
                "service": name, "status": status,
                "status_name": SERVICE_STATUSES.get(status, "unknown"),
                "stored_result": read_result(reader, address + 0x28),
            }
            if read_pointer(reader, address) != vtable:
                raise RuntimeError("Service object changed")
    if (read_pointer(reader, base + SERVICE_CONTAINER_RVA) != container
            or read_pointer(reader, container + 0x30) != registry):
        raise RuntimeError("Service registry changed")
    return {"initialized": True, "services": sorted(services.values(), key=lambda s: s["service"])}


def read_flag(reader: MemoryReader, address: int, offsets: tuple[int, int]) -> bool | None:
    """Follow one pointer and read a bool behind it, None when the pointer is null."""
    pointer = read_pointer(reader, address + offsets[0])
    return bool(read_exact(reader, pointer + offsets[1], 1)[0]) if pointer else None


def sample_game_players(reader: MemoryReader, base: int) -> dict:
    service = read_pointer(reader, base + PLAYER_SERVICE_RVA)
    if not service:
        return {"initialized": False}
    if read_pointer(reader, service) != base + PLAYER_SERVICE_VTABLE_RVA:
        raise RuntimeError("Unexpected player service")
    players = []
    for player in read_pointer_array(reader, service + 0x18):
        game_mode_player = read_pointer(reader, player + GAME_MODE_PLAYER_OFFSET)
        players.append({
            "player_class_ok": read_pointer(reader, player) == base + PLAYER_VTABLE_RVA,
            "game_mode_player": bool(game_mode_player),
            "world_loaded": read_flag(reader, game_mode_player, WORLD_STATE_OFFSETS) if game_mode_player else None,
        })
    result = {"initialized": True, "player_count": len(players), "players": players}

    coop = read_pointer(reader, base + COOP_SERVICE_RVA)
    if coop:
        if read_pointer(reader, coop) != base + COOP_SERVICE_VTABLE_RVA:
            raise RuntimeError("Unexpected coop service")
        result["coop_ready_to_send_mblocks"] = read_flag(reader, coop, COOP_MBLOCK_READY_OFFSETS)
        result["coop_mblock_sync_state"] = int.from_bytes(
            read_exact(reader, coop + COOP_MBLOCK_SYNC_STATE_OFFSET, 4), "little"
        )
    if (read_pointer(reader, base + PLAYER_SERVICE_RVA) != service
            or read_pointer(reader, base + COOP_SERVICE_RVA) != coop):
        raise RuntimeError("Game services changed")
    return result


def member_peer_id(reader: MemoryReader, member: int, session_id: int) -> int | None:
    """Lower-bound search of the member's per-session peer map, as in RVA 0xd1f860."""
    node = read_pointer(reader, member + MEMBER_PEER_TREE_OFFSET + 0x10)
    found = None
    for _ in range(MAX_TREE_DEPTH):
        if not node:
            break
        if int.from_bytes(read_exact(reader, node + 0x20, 4), "little") >= session_id:
            found, node = node, read_pointer(reader, node)
        else:
            node = read_pointer(reader, node + 8)
    else:
        raise RuntimeError("Peer map is deeper than expected")
    if found is None or int.from_bytes(read_exact(reader, found + 0x20, 4), "little") != session_id:
        return None
    return int.from_bytes(read_exact(reader, found + 0x24, 4), "little")


def sample_peer_mapping(reader: MemoryReader, base: int) -> dict:
    """Which game-session members CPlayerService::GetPlayerFromPeerId can resolve to a player."""
    manager = read_pointer(reader, base + SESSION_MANAGER_RVA)
    if not manager:
        return {"initialized": False}
    session_id = int.from_bytes(read_exact(reader, manager + GAME_SESSION_ID_OFFSET, 4), "little")
    session = next((int(item["address"], 16) for item in sample_sessions(reader, base)["sessions"]
                    if item["session_id"] == session_id), None)
    if session is None:
        return {"initialized": True, "game_session_found": False}
    service = read_pointer(reader, base + PLAYER_SERVICE_RVA)
    if service and read_pointer(reader, service) != base + PLAYER_SERVICE_VTABLE_RVA:
        raise RuntimeError("Unexpected player service")
    players = read_pointer_array(reader, service + 0x18) if service else ()
    player_members = {read_pointer(reader, player + PLAYER_MEMBER_OFFSET) for player in players}
    members = read_pointer_array(reader, session + SESSION_MEMBERS_OFFSET)
    return {
        "initialized": True, "game_session_found": True,
        "members": [{"peer_id": member_peer_id(reader, member, session_id),
                     "has_player": member in player_members} for member in members],
        "players_without_member": len(player_members - set(members)),
    }


def sample_join_state(reader: MemoryReader, base: int) -> dict:
    result = {}
    for name, sample in (
        ("network", sample_network), ("platform", sample_platform),
        ("mode", sample_mode), ("online_services", sample_services),
        ("game_players", sample_game_players), ("peer_mapping", sample_peer_mapping),
    ):
        try:
            result[name] = sample(reader, base)
        except RuntimeError:
            # Fixed text only, exception messages may contain addresses
            result[name] = {"error": "read_failed_or_changed"}
    return result


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def record_changes(sample: Callable[[], dict], duration: float, interval: float) -> Iterator[dict]:
    started = time.monotonic()
    previous = None
    samples = changes = 0
    while (elapsed := time.monotonic() - started) < duration:
        state = sample()
        samples += 1
        if state != previous:
            changes += 1
            yield {"event": "state", "utc": utc_now(), "elapsed_seconds": round(elapsed, 3),
                   "state": state}
            previous = state
        time.sleep(min(interval, duration - elapsed))
    yield {"event": "end", "utc": utc_now(), "elapsed_seconds": round(elapsed, 3),
           "samples": samples, "changes": changes}
