"""Raise the Storm peer limit that the CSession constructor hard-codes to two.

OnlineSession::CSession::CSession (RVA 0xcd2b40) embeds the Storm echo session
configuration at Session+0x48. Its maxPeers property value is Session+0x158 and its
maxPeersId value is Session+0x178. The constructor sets both to two for every online
session, and CCreateStormSessionOperation later creates the peer-to-peer session from
this configuration. Game slot counters and descriptors at +0x3e0 and +0x439 are not
involved, so the earlier capacity patches left this transport limit at two.

The patch changes the five immediates of that block from two to four. The block stays
the same length and instruction boundaries do not move. Game-level admission in
OnJoinRequest still limits every session to its own descriptor capacity.
"""

from fc6.build import STEAM, UBISOFT, Build
from fc6.edits import ByteEdit


STORM_MAX_PEERS = 4
SESSION_STORM_MAX_PEERS_OFFSET = 0x158
SESSION_STORM_MAX_PEERS_ID_OFFSET = 0x178

BLOCK_RVA = 0xCD2CF6
ORIGINAL_BLOCK = bytes.fromhex(
    "837b18027427"            # cmp dword [rbx+0x18], 2 ; je   (maxPeers already two)
    "488b4308488bcbc6431001c60001488b03ff503084c07408488bcbe8d48b3804"
    "c7431802000000"          # mov dword [rbx+0x18], 2      (maxPeers = 2)
    "4183bf5801000002"        # cmp dword [r15+0x158], 2
    "7734"                    # ja                            (maxPeers above two)
    "498d9f60010000"          # lea rbx, [r15+0x160]          (maxPeersId property)
    "837b18027427"            # cmp dword [rbx+0x18], 2 ; je
    "488b4308488bcbc6431001c60001488b03ff503084c07408488bcbe8968b3804"
    "c7431802000000"          # mov dword [rbx+0x18], 2      (maxPeersId = 2)
)
# The two property setter calls are relative, so other builds differ in their displacements
ORIGINAL_BLOCKS = {
    STEAM.name: ORIGINAL_BLOCK,
    UBISOFT.name: ORIGINAL_BLOCK[:0x23] + b"\xb4" + ORIGINAL_BLOCK[0x24:0x61] + b"\xb4" + ORIGINAL_BLOCK[0x62:],
}
# Offsets of the five immediates inside ORIGINAL_BLOCK
IMMEDIATE_OFFSETS = (0x03, 0x29, 0x34, 0x41, 0x67)


def patched_block(peers: int = STORM_MAX_PEERS, build: Build = STEAM) -> bytes:
    if not 1 <= peers <= 0x7F:
        raise ValueError("Storm peer limit must fit the signed imm8 compares")
    block = bytearray(ORIGINAL_BLOCKS[build.name])
    for offset in IMMEDIATE_OFFSETS:
        if block[offset] != 2:
            raise AssertionError(f"Unexpected immediate at block offset {offset:#x}")
        block[offset] = peers
    return bytes(block)


def patched_code_probes(build: Build = STEAM) -> dict[int, bytes]:
    return {build.rva(BLOCK_RVA): patched_block(build=build)}


def build_edits(build: Build = STEAM) -> tuple[ByteEdit, ...]:
    original = ORIGINAL_BLOCKS[build.name]
    offset = build.file_offset(build.rva(BLOCK_RVA), len(original))
    return (ByteEdit(offset, original, patched_block(build=build)),)
