"""Raise the copied game-mode team capacity from two to four for selected co-op modes.

CGameModeConfiguration is copied on three paths. Each copy of byte +0x39 (maxTeamSize)
is replaced by a call to a leaf stub in .text1 padding that writes four instead of two
when the source mode ID at +0x18 is listed in the profile.
"""

import struct
from dataclasses import dataclass

from fc6.build import STEAM, TEXT1, Build
from fc6.edits import ByteEdit


CAMPAIGN_MODE_ID = 0x6A3C926F
OPERATION_MODE_ID = 0x9B7024CE
INSIDE_THE_MIND_MODE_ID = 0xDA8F2C61
TARGET_CAPACITY = 4

# (RVA of the 7-byte movzx/mov pair, register that holds the source configuration)
COPY_SITES = (
    (0xC5597C, "rbx"),
    (0xC5BE63, "rbx"),
    (0xB83DE71, "rdi"),
)
ORIGINAL_COPY_CODE = {
    "rdi": bytes.fromhex("0fb64739884339"),  # movzx eax, [rdi+0x39]; mov [rbx+0x39], al
    "rbx": bytes.fromhex("0fb64339884739"),  # movzx eax, [rbx+0x39]; mov [rdi+0x39], al
}
STUB_LAYOUTS = {
    # load capacity, compare mode ID prefix, store capacity and return
    "rdi": ("0fb64739", "817f18", "884339c3"),
    "rbx": ("0fb64339", "817b18", "884739c3"),
}


@dataclass(frozen=True)
class PatchProfile:
    mode_ids: tuple[int, ...]
    stub_rvas: dict[str, int]


PROFILES = {
    "campaign": PatchProfile((CAMPAIGN_MODE_ID,), {"rdi": TEXT1.rva + 0x20, "rbx": TEXT1.rva + 0x40}),
    "coop-dlc": PatchProfile(
        (CAMPAIGN_MODE_ID, OPERATION_MODE_ID, INSIDE_THE_MIND_MODE_ID),
        {"rdi": TEXT1.rva + 0x20, "rbx": TEXT1.rva + 0x60},
    ),
}


def get_profile(name: str) -> PatchProfile:
    try:
        return PROFILES[name]
    except KeyError as error:
        raise ValueError(f"Unsupported patch profile {name}") from error


def build_capacity_stub(source_register: str, profile: str = "campaign") -> bytes:
    if source_register not in STUB_LAYOUTS:
        raise ValueError(f"Unknown source register {source_register}")
    settings = get_profile(profile)
    load, compare, store = (bytes.fromhex(value) for value in STUB_LAYOUTS[source_register])
    if profile == "campaign":
        # The first published build used this shorter single-mode form. Keep it byte-identical.
        return (
            load
            + compare
            + struct.pack("<I", CAMPAIGN_MODE_ID)
            + bytes.fromhex("75063c027502b0")
            + bytes([TARGET_CAPACITY])
            + store
        )

    code = bytearray(load + bytes.fromhex("3c02"))
    capacity_branch = len(code)
    code += bytes.fromhex("7500")
    mode_branches = []
    for index, mode_id in enumerate(settings.mode_ids):
        code += compare + struct.pack("<I", mode_id)
        branch = len(code)
        last_mode = index == len(settings.mode_ids) - 1
        code += bytes([0x75 if last_mode else 0x74, 0])
        mode_branches.append((branch, last_mode))
    promote = len(code)
    code += bytes([0xB0, TARGET_CAPACITY])
    write = len(code)
    code += store
    code[capacity_branch + 1] = write - capacity_branch - 2
    for branch, last_mode in mode_branches:
        code[branch + 1] = (write if last_mode else promote) - branch - 2
    return bytes(code)


def _call_site(rva: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - rva - 5) + b"\x90\x90"


def patched_code_probes(profile: str = "campaign", build: Build = STEAM) -> dict[int, bytes]:
    """Keyed by RVAs of the given build. The stubs are position independent, the calls are not."""
    settings = get_profile(profile)
    stubs = {register: build.rva(rva) for register, rva in settings.stub_rvas.items()}
    probes = {rva: build_capacity_stub(register, profile) for register, rva in stubs.items()}
    for rva, register in COPY_SITES:
        probes[build.rva(rva)] = _call_site(build.rva(rva), stubs[register])
    return probes


def text1_end(profile: str = "campaign") -> int:
    settings = get_profile(profile)
    return max(rva + len(build_capacity_stub(register, profile)) for register, rva in settings.stub_rvas.items())


def build_edits(profile: str = "campaign", build: Build = STEAM) -> tuple[ByteEdit, ...]:
    """Code edits only. The variant adds the shared .text1 VirtualSize edit."""
    settings = get_profile(profile)
    probes = patched_code_probes(profile, build)
    edits = []
    for rva, register in COPY_SITES:
        rva = build.rva(rva)
        edits.append(ByteEdit(build.file_offset(rva, 7), ORIGINAL_COPY_CODE[register], probes[rva]))
    for rva in settings.stub_rvas.values():
        rva = build.rva(rva)
        stub = probes[rva]
        edits.append(ByteEdit(build.file_offset(rva, len(stub)), bytes(len(stub)), stub))
    return tuple(sorted(edits, key=lambda edit: edit.offset))
