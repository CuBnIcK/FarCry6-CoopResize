"""Ask the sessions API for four slots by adding overrides.maxTeamSize to CreateSession.

The CCreateSessionOperation request builder is hooked at one instruction. For the
co-op mode IDs of the coop-dlc profile, a non-leaf stub looks up the request's
overrides.maxTeamSize JSON node with the game's own getter and stores four into it,
either as a number or as the string "4" used by the original overrides serializer.
The stub calls other functions, so it gets UNWIND_INFO and a RUNTIME_FUNCTION entry.
"""

import bisect
import struct
from pathlib import Path

from fc6 import capacity
from fc6.build import EXCEPTION_TABLE_RVA, STEAM, Build
from fc6.edits import ByteEdit


REQUEST_HOOK_RVA = 0xC769AF
REQUEST_HOOK_ORIGINAL = bytes.fromhex("498b8ee0000000")  # mov rcx, [r14+0xe0]
REQUEST_STUB_RVA = 0x1E9F80A0
REQUEST_UNWIND_RVA = 0x1E9F8120
REQUEST_UNWIND_INFO = bytes.fromhex("0104010004420000")  # version 1, prolog 4, sub rsp, 0x28
STRING_REQUEST_UNWIND_RVA = 0x1E9F8140
REQUEST_STRING_RVA = 0x1E9F8150
REQUEST_STRING = b"4\0"

JSON_GET_MEMBER_RVA = 0x22FB20
JSON_SET_CAPACITY_RVA = 0x22F190
JSON_UTF8_SET_RVA = 0x208690
JSON_NULL_RVA = 0x6A45958
# lea rax, [JSON null] inside the original string setter, proves the singleton address
JSON_STRING_SETTER_NULL_REFERENCE_RVA = 0x22F14B
OVERRIDES_STRING_RVA = 0x58E1598
MAX_TEAM_SIZE_STRING_RVA = 0x58E0638

EXCEPTION_INSERT_INDEX = STEAM.exception_insert_index
EXCEPTION_INSERT_RVA = EXCEPTION_TABLE_RVA + EXCEPTION_INSERT_INDEX * 12
RUNTIME_FUNCTION_SIZE = 12


def build_request_stub(string_override: bool = False, build: Build = STEAM) -> bytes:
    code = bytearray.fromhex("4883ec28")
    branches = []
    modes = capacity.get_profile("coop-dlc").mode_ids
    for index, mode_id in enumerate(modes):
        code += bytes.fromhex("4181be70010000") + struct.pack("<I", mode_id)
        last = index == len(modes) - 1
        branches.append((len(code), last))
        code += bytes([0x75 if last else 0x74, 0])
    promote = len(code)
    code += bytes.fromhex("488d8c24a0000000")  # lea rcx, [caller rsp + 0x70], the request JSON root

    stub = build.rva(REQUEST_STUB_RVA)

    def load_key(rva):
        displacement = build.rva(rva) - stub - len(code) - 7
        code.extend(bytes.fromhex("488d15") + struct.pack("<i", displacement))

    def call(rva):
        displacement = build.rva(rva) - stub - len(code) - 5
        code.extend(b"\xe8" + struct.pack("<i", displacement))

    load_key(OVERRIDES_STRING_RVA)
    call(JSON_GET_MEMBER_RVA)
    code += bytes.fromhex("488bc8")
    load_key(MAX_TEAM_SIZE_STRING_RVA)
    call(JSON_GET_MEMBER_RVA)
    null_branch = None
    if string_override:
        load_key(JSON_NULL_RVA)
        code += bytes.fromhex("483bc2")
        null_branch = len(code)
        code += bytes.fromhex("7400")
        code += bytes.fromhex("4889442420488d4820")
        load_key(REQUEST_STRING_RVA)
        call(JSON_UTF8_SET_RVA)
        code += bytes.fromhex("488b442420c7403000000000")  # value type 0, string
    else:
        code += bytes.fromhex("488bc8ba") + struct.pack("<I", capacity.TARGET_CAPACITY)
        call(JSON_SET_CAPACITY_RVA)
    restore = len(code)
    code += REQUEST_HOOK_ORIGINAL + bytes.fromhex("4883c428c3")
    for branch, last in branches:
        code[branch + 1] = (restore if last else promote) - branch - 2
    if null_branch is not None:
        code[null_branch + 1] = restore - null_branch - 2
    return bytes(code)


def unwind_rva(string_override: bool = False) -> int:
    """Reference RVA, translate it with Build.rva."""
    return STRING_REQUEST_UNWIND_RVA if string_override else REQUEST_UNWIND_RVA


def text1_end(string_override: bool = False) -> int:
    if string_override:
        return REQUEST_STRING_RVA + len(REQUEST_STRING)
    return REQUEST_UNWIND_RVA + len(REQUEST_UNWIND_INFO)


def runtime_function_entry(string_override: bool = False, build: Build = STEAM) -> bytes:
    stub = build.rva(REQUEST_STUB_RVA)
    return struct.pack(
        "<III", stub, stub + len(build_request_stub(string_override, build)),
        build.rva(unwind_rva(string_override)),
    )


def exception_insert_rva(build: Build = STEAM) -> int:
    return build.exception_table_rva + build.exception_insert_index * RUNTIME_FUNCTION_SIZE


def add_runtime_function(table: bytes, string_override: bool = False, build: Build = STEAM) -> bytes:
    if len(table) % RUNTIME_FUNCTION_SIZE:
        raise ValueError("Runtime function table length is not a multiple of twelve")
    entries = list(struct.iter_unpack("<III", table))
    starts = [entry[0] for entry in entries]
    if any(start >= end for start, end, _ in entries):
        raise ValueError("Runtime function range is invalid")
    if any(left >= right for left, right in zip(starts, starts[1:])):
        raise ValueError("Runtime function table is not sorted")
    stub = build.rva(REQUEST_STUB_RVA)
    index = bisect.bisect_left(starts, stub)
    end = stub + len(build_request_stub(string_override, build))
    if index and entries[index - 1][1] > stub:
        raise ValueError("Request stub overlaps an existing runtime function")
    if index < len(entries) and end > entries[index][0]:
        raise ValueError("Request stub overlaps an existing runtime function")
    offset = index * RUNTIME_FUNCTION_SIZE
    return table[:offset] + runtime_function_entry(string_override, build) + table[offset:]


def patched_code_probes(string_override: bool = False, build: Build = STEAM) -> dict[int, bytes]:
    """Loaded-image checks for this component alone, including the mapped PE header fields."""
    hook, stub = build.rva(REQUEST_HOOK_RVA), build.rva(REQUEST_STUB_RVA)
    exceptions = build.exception_section
    probes = {
        hook: b"\xe8" + struct.pack("<i", stub - hook - 5) + b"\x90\x90",
        stub: build_request_stub(string_override, build),
        build.rva(unwind_rva(string_override)): REQUEST_UNWIND_INFO,
        exception_insert_rva(build): runtime_function_entry(string_override, build),
        build.exception_directory_size_field: struct.pack(
            "<I", build.exception_table_size + RUNTIME_FUNCTION_SIZE
        ),
        exceptions.virtual_size_field: struct.pack("<I", exceptions.virtual_size + RUNTIME_FUNCTION_SIZE),
        build.rva(JSON_GET_MEMBER_RVA): bytes.fromhex("405541564157488bec4883ec704c8bf2"),
    }
    if string_override:
        null_reference = build.rva(JSON_STRING_SETTER_NULL_REFERENCE_RVA)
        probes[build.rva(REQUEST_STRING_RVA)] = REQUEST_STRING
        probes[build.rva(JSON_UTF8_SET_RVA)] = bytes.fromhex("4c8bca4c8bd14885d27458488bc2410f")
        probes[null_reference] = bytes.fromhex("488d05") + struct.pack(
            "<i", build.rva(JSON_NULL_RVA) - null_reference - 7
        )
    else:
        # Up to the RIP displacement of the security cookie load, which differs between builds
        probes[build.rva(JSON_SET_CAPACITY_RVA)] = bytes.fromhex("4c8bdc534881ecd0000000488b05")
    return probes


def build_edits(source: Path, string_override: bool = False, build: Build = STEAM) -> tuple[ByteEdit, ...]:
    """Code, unwind and exception-directory edits. The variant adds the .text1 VirtualSize edit."""
    table_size = build.exception_table_size
    table_offset = build.file_offset(build.exception_table_rva, table_size + RUNTIME_FUNCTION_SIZE)
    with source.open("rb") as stream:
        stream.seek(table_offset)
        original = stream.read(table_size)
        padding = stream.read(RUNTIME_FUNCTION_SIZE)
    if len(original) != table_size or padding != bytes(RUNTIME_FUNCTION_SIZE):
        raise ValueError("Runtime function table or following padding is unexpected")
    updated = add_runtime_function(original, string_override, build)
    insertion = build.exception_insert_index * RUNTIME_FUNCTION_SIZE
    if updated[insertion:insertion + RUNTIME_FUNCTION_SIZE] != runtime_function_entry(string_override, build):
        raise ValueError("Runtime function insertion position differs from the supported build")

    probes = patched_code_probes(string_override, build)
    hook, stub_rva = build.rva(REQUEST_HOOK_RVA), build.rva(REQUEST_STUB_RVA)
    unwind = build.rva(unwind_rva(string_override))
    stub = probes[stub_rva]
    exceptions = build.exception_section
    edits = [
        ByteEdit(build.file_offset(hook, 7), REQUEST_HOOK_ORIGINAL, probes[hook]),
        ByteEdit(build.file_offset(stub_rva, len(stub)), bytes(len(stub)), stub),
        ByteEdit(build.file_offset(unwind, len(REQUEST_UNWIND_INFO)),
                 bytes(len(REQUEST_UNWIND_INFO)), REQUEST_UNWIND_INFO),
        ByteEdit(build.exception_directory_size_field, struct.pack("<I", table_size),
                 probes[build.exception_directory_size_field]),
        ByteEdit(exceptions.virtual_size_field, struct.pack("<I", exceptions.virtual_size),
                 probes[exceptions.virtual_size_field]),
        ByteEdit(table_offset + insertion, original[insertion:] + padding, updated[insertion:]),
    ]
    if string_override:
        literal = build.rva(REQUEST_STRING_RVA)
        edits.append(ByteEdit(build.file_offset(literal, len(REQUEST_STRING)),
                              bytes(len(REQUEST_STRING)), REQUEST_STRING))
    return tuple(sorted(edits, key=lambda edit: edit.offset))
