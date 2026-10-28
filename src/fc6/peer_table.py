"""Let P2P network objects work with peer ids 2 and 3.

FC6 dropped Far Cry 5's arcade multiplayer and sizes the per-peer replica table of its
session object for two peers. The object constructed at RVA 0xcd1bc0 keeps a uint32
vector at +0x60 with two entries, one per peer id, and its methods refuse higher ids:

  0xd4f854  OnReplicaResolved (marks 1)    cmp ecx, 2 ; jb      ObjectRefIdInvalid for id >= 2
  0xd508f1  replica ready (marks 2)        cmp r15d, 2 ; jb     same
  0xd4f29a  replica gone (clears)          cmp [r8+0x38], 2 ; jb
  0xbfc5dfa session send to a peer         cmp edx, 1 ; ja      message silently dropped

With storm-peers the Storm session hands out ids up to 3, so a third player got id 2 or 3,
was never registered for any P2P object and never received the host's world state
(Trapper-B2FE5BAD). This component grows the table to four entries and raises the four
checks to match. The 4-entry vector no longer fits the inline buffer and is reallocated on
the heap by the game's own vector insert (0xd2ad50 -> 0x28fd80).
"""

from fc6.build import STEAM, Build
from fc6.edits import ByteEdit


PEER_LIMIT = 4
# (RVA of the instruction, original bytes, patched bytes, description)
SITES = (
    (0xCD1C1F, bytes.fromhex("448d4602"), bytes.fromhex("448d4604"), "lea r8d, [rsi+N], table size"),
    (0xBFC5DFA, bytes.fromhex("83fa01"), bytes.fromhex("83fa03"), "cmp edx, N, highest peer id for sends"),
    (0xD4F854, bytes.fromhex("83f902"), bytes.fromhex("83f904"), "cmp ecx, N, replica resolved"),
    (0xD508F1, bytes.fromhex("4183ff02"), bytes.fromhex("4183ff04"), "cmp r15d, N, replica ready"),
    (0xD4F29A, bytes.fromhex("4183783802"), bytes.fromhex("4183783804"), "cmp dword [r8+0x38], N, replica gone"),
)


# Listener methods in the vtable at 0x58ed1f0 that validate a peer id and store it as the object's
# peer at +0x74, then switch the object state. They index no table, so the limit is plain validation.
# With only the replica table fixed, the host accepted a peer-2 player but never spawned him.
OWNER_SITES = (
    (0xD45878, bytes.fromhex("83783802"), bytes.fromhex("83783804"), "cmp dword [rax+0x38], N, 0xd45850"),
    (0xD45CDF, bytes.fromhex("4183783802"), bytes.fromhex("4183783804"), "cmp dword [r8+0x38], N, 0xd45cd0"),
    (0xD45D6D, bytes.fromhex("83f802"), bytes.fromhex("83f804"), "cmp eax, N, 0xd45d60"),
)


def _probes(sites, build: Build) -> dict[int, bytes]:
    return {build.rva(rva): patched for rva, _, patched, _ in sites}


def _edits(sites, build: Build) -> tuple[ByteEdit, ...]:
    edits = (ByteEdit(build.file_offset(build.rva(rva), len(original)), original, patched)
             for rva, original, patched, _ in sites)
    return tuple(sorted(edits, key=lambda edit: edit.offset))


def patched_code_probes(build: Build = STEAM) -> dict[int, bytes]:
    return _probes(SITES, build)


def build_edits(build: Build = STEAM) -> tuple[ByteEdit, ...]:
    return _edits(SITES, build)


def owner_code_probes(build: Build = STEAM) -> dict[int, bytes]:
    return _probes(OWNER_SITES, build)


def build_owner_edits(build: Build = STEAM) -> tuple[ByteEdit, ...]:
    return _edits(OWNER_SITES, build)
