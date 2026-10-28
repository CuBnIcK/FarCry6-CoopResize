import ctypes
import struct
import unittest
from pathlib import Path

import capstone
from fc6_support import NATIVE_X64, ORIGINAL_DLL

from fc6 import capacity
from fc6 import session_request as patcher
from fc6.build import STEAM, file_offset
from fc6.edits import ByteEdit
from fc6.variants import get_variant


CAMPAIGN_MODE_ID = 0x6A3C926F
OPERATION_MODE_ID = 0x9B7024CE
INSIDE_THE_MIND_MODE_ID = 0xDA8F2C61
MAIN_MENU_MODE_ID = 0x83AE70EF
DLC_Y2_MODE_ID = 0x6BE16A15
NATIVE_CODE_SIZE = 0x1000
REQUEST_WRAPPER_STUB_OFFSET = 0x80
GET_MEMBER_THUNK_OFFSET = 0x300
SET_CAPACITY_THUNK_OFFSET = 0x400
OVERRIDES_KEY_OFFSET = 0x500
MAX_TEAM_SIZE_KEY_OFFSET = 0x520
REQUEST_STRING_OFFSET = 0x540
JSON_NULL_OFFSET = 0x560
ROOT_MARKER = 0xA1B2C3D4E5F60718
INITIAL_VALUE_TYPE = 0xDEADBEEF
NUMERIC_REQUEST_SHA256 = "566975b0126df772b6513b24758eaef8e92928f305c427d62da901c1c86be67b"


class CallProbe(ctypes.Structure):
    _fields_ = [
        ("stack_alignment", ctypes.c_uint64),
        ("home_space_written", ctypes.c_uint64),
        ("stack_pointer", ctypes.c_uint64),
    ]


def _probe_thunk(diagnostics: CallProbe, callback_address: int) -> bytes:
    code = bytearray.fromhex("4989e249bb")
    code.extend(struct.pack("<Q", ctypes.addressof(diagnostics) + CallProbe.stack_pointer.offset))
    code.extend(bytes.fromhex("4d89134983e20f49bb"))
    code.extend(struct.pack("<Q", ctypes.addressof(diagnostics)))
    code.extend(bytes.fromhex("4d8913"))
    for offset, value in ((8, 0x1122334455667788), (0x10, 0x2233445566778899), (0x18, 0x33445566778899AA), (0x20, 0x445566778899AABB)):
        code.extend(b"\x49\xba" + struct.pack("<Q", value))
        code.extend(bytes.fromhex("4c895424") + bytes([offset]))
    code.extend(b"\x49\xba" + struct.pack("<Q", 1))
    code.extend(b"\x49\xbb" + struct.pack("<Q", ctypes.addressof(diagnostics) + CallProbe.home_space_written.offset))
    code.extend(bytes.fromhex("4d8913"))
    code.extend(b"\x49\xbb" + struct.pack("<Q", callback_address))
    code.extend(bytes.fromhex("41ffe3"))
    return bytes(code)


def _relocate_request_stub(
    stub: bytes,
    source_rva: int,
    destination: int,
    call_targets: dict[int, int],
    rip_targets: dict[int, int],
    string_override: bool = False,
) -> bytes:
    code = bytearray(stub)
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = True
    call_counts = {target: 0 for target in call_targets}
    rip_counts = {target: 0 for target in rip_targets}
    for instruction in disassembler.disasm(stub, source_rva):
        offset = instruction.address - source_rva
        if instruction.mnemonic == "call" and instruction.operands[0].type == capstone.x86.X86_OP_IMM:
            target = instruction.operands[0].imm
            if target in call_targets:
                replacement = call_targets[target]
                displacement = replacement - (destination + offset + instruction.size)
                struct.pack_into("<i", code, offset + instruction.imm_offset, displacement)
                call_counts[target] += 1
        if instruction.mnemonic == "lea":
            for operand in instruction.operands:
                if operand.type != capstone.x86.X86_OP_MEM or operand.mem.base != capstone.x86.X86_REG_RIP:
                    continue
                target = instruction.address + instruction.size + operand.mem.disp
                if target in rip_targets:
                    replacement = rip_targets[target]
                    displacement = replacement - (destination + offset + instruction.size)
                    struct.pack_into("<i", code, offset + instruction.disp_offset, displacement)
                    rip_counts[target] += 1
    setter_rva = patcher.JSON_UTF8_SET_RVA if string_override else patcher.JSON_SET_CAPACITY_RVA
    expected_calls = {patcher.JSON_GET_MEMBER_RVA: 2, setter_rva: 1}
    if call_counts != expected_calls:
        raise AssertionError(f"Unexpected request stub calls {call_counts}")
    expected_strings = {
        patcher.OVERRIDES_STRING_RVA: 1,
        patcher.MAX_TEAM_SIZE_STRING_RVA: 1,
    }
    if string_override:
        expected_strings[patcher.JSON_NULL_RVA] = 1
        expected_strings[patcher.REQUEST_STRING_RVA] = 1
    if rip_counts != expected_strings:
        raise AssertionError(f"Unexpected request stub string references {rip_counts}")
    return bytes(code)


class NativeRequestHook:
    def __init__(self, string_override: bool = False, return_json_null: bool = False):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
        kernel.VirtualAlloc.restype = ctypes.c_void_p
        kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        kernel.VirtualProtect.restype = ctypes.c_int
        kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        kernel.VirtualFree.restype = ctypes.c_int
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        kernel.FlushInstructionCache.restype = ctypes.c_int
        self.kernel = kernel
        self.string_override = string_override
        self.return_json_null = return_json_null
        self.getter_probe = CallProbe()
        self.setter_probe = CallProbe()
        self.overrides_node = ctypes.c_uint64(0x1020304050607080)
        self.capacity_node = ctypes.create_string_buffer(0x38)
        self.overrides_pointer = ctypes.addressof(self.overrides_node)
        self.capacity_pointer = ctypes.addressof(self.capacity_node)
        self.expected_marker_pointer = 0
        self.root_slot_pointer = 0
        self.get_calls = []
        self.set_calls = []
        self.root_markers_valid = []
        self.overrides_markers_valid = []
        self.unexpected_keys = []
        getter_type = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
        self.getter_callback = getter_type(self._get_member)
        if string_override:
            setter_type = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)
            self.setter_callback = setter_type(self._set_capacity_string)
        else:
            setter_type = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32)
            self.setter_callback = setter_type(self._set_capacity_number)
        self.getter_callback_address = ctypes.cast(self.getter_callback, ctypes.c_void_p).value
        self.setter_callback_address = ctypes.cast(self.setter_callback, ctypes.c_void_p).value
        self.address = kernel.VirtualAlloc(None, NATIVE_CODE_SIZE, 0x3000, 0x04)
        if not self.address:
            raise ctypes.WinError(ctypes.get_last_error())
        self.address = int(self.address)
        self.json_null_pointer = self.address + JSON_NULL_OFFSET
        try:
            self._install_code()
        except BaseException:
            kernel.VirtualFree(self.address, 0, 0x8000)
            raise

    def _get_member(self, object_pointer, key_pointer):
        key = ctypes.string_at(key_pointer)
        self.get_calls.append((object_pointer, key))
        if key == b"overrides":
            expected_slot = self.getter_probe.stack_pointer + 0xA8
            valid = object_pointer == expected_slot
            if valid:
                valid = ctypes.c_void_p.from_address(object_pointer).value == self.expected_marker_pointer
            self.root_markers_valid.append(valid)
            self.root_slot_pointer = object_pointer
            return self.overrides_pointer
        if key == b"maxTeamSize":
            self.overrides_markers_valid.append(object_pointer == self.overrides_pointer)
            if self.return_json_null:
                return self.json_null_pointer
            return self.capacity_pointer
        self.unexpected_keys.append(key)
        return None

    def _set_capacity_number(self, node_pointer, value):
        self.set_calls.append((node_pointer, value))

    def _set_capacity_string(self, field_pointer, value_pointer):
        self.set_calls.append((field_pointer, ctypes.string_at(value_pointer)))

    def _install_code(self):
        base = self.address
        source_stub = patcher.build_request_stub(string_override=self.string_override)
        setter_rva = patcher.JSON_UTF8_SET_RVA if self.string_override else patcher.JSON_SET_CAPACITY_RVA
        rip_targets = {
            patcher.OVERRIDES_STRING_RVA: base + OVERRIDES_KEY_OFFSET,
            patcher.MAX_TEAM_SIZE_STRING_RVA: base + MAX_TEAM_SIZE_KEY_OFFSET,
        }
        if self.string_override:
            rip_targets[patcher.JSON_NULL_RVA] = base + JSON_NULL_OFFSET
            rip_targets[patcher.REQUEST_STRING_RVA] = base + REQUEST_STRING_OFFSET
        relocated_stub = _relocate_request_stub(
            source_stub,
            patcher.REQUEST_STUB_RVA,
            base + REQUEST_WRAPPER_STUB_OFFSET,
            {
                patcher.JSON_GET_MEMBER_RVA: base + GET_MEMBER_THUNK_OFFSET,
                setter_rva: base + SET_CAPACITY_THUNK_OFFSET,
            },
            rip_targets,
            self.string_override,
        )
        wrapper_prefix = bytes.fromhex("41564989ce4881ec800000004889542470")
        call_offset = len(wrapper_prefix)
        call = b"\xe8" + struct.pack("<i", REQUEST_WRAPPER_STUB_OFFSET - call_offset - 5)
        wrapper = wrapper_prefix + call + bytes.fromhex("4889c84881c480000000415ec3")
        getter_thunk = _probe_thunk(self.getter_probe, self.getter_callback_address)
        setter_thunk = _probe_thunk(self.setter_probe, self.setter_callback_address)
        if len(wrapper) > REQUEST_WRAPPER_STUB_OFFSET:
            raise AssertionError("Request wrapper overlaps the native stub")
        if len(getter_thunk) > SET_CAPACITY_THUNK_OFFSET - GET_MEMBER_THUNK_OFFSET:
            raise AssertionError("GetMember probe overlaps SetCapacity probe")
        if len(setter_thunk) > OVERRIDES_KEY_OFFSET - SET_CAPACITY_THUNK_OFFSET:
            raise AssertionError("SetCapacity probe overlaps request strings")
        image = bytearray(b"\xcc" * NATIVE_CODE_SIZE)
        image[:len(wrapper)] = wrapper
        image[REQUEST_WRAPPER_STUB_OFFSET:REQUEST_WRAPPER_STUB_OFFSET + len(relocated_stub)] = relocated_stub
        image[GET_MEMBER_THUNK_OFFSET:GET_MEMBER_THUNK_OFFSET + len(getter_thunk)] = getter_thunk
        image[SET_CAPACITY_THUNK_OFFSET:SET_CAPACITY_THUNK_OFFSET + len(setter_thunk)] = setter_thunk
        image[OVERRIDES_KEY_OFFSET:OVERRIDES_KEY_OFFSET + 10] = b"overrides\0"
        image[MAX_TEAM_SIZE_KEY_OFFSET:MAX_TEAM_SIZE_KEY_OFFSET + 12] = b"maxTeamSize\0"
        if self.string_override:
            image[REQUEST_STRING_OFFSET:REQUEST_STRING_OFFSET + 2] = b"4\0"
            image[JSON_NULL_OFFSET:JSON_NULL_OFFSET + 8] = bytes(8)
        ctypes.memmove(base, bytes(image), len(image))
        old_protection = ctypes.c_ulong()
        if not self.kernel.VirtualProtect(base, len(image), 0x20, ctypes.byref(old_protection)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.kernel.FlushInstructionCache(self.kernel.GetCurrentProcess(), base, len(image)):
            raise ctypes.WinError(ctypes.get_last_error())
        function_type = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
        self.function = function_type(base)

    def invoke(self, mode_id: int) -> int | None:
        self.get_calls.clear()
        self.set_calls.clear()
        self.root_markers_valid.clear()
        self.overrides_markers_valid.clear()
        self.unexpected_keys.clear()
        self.getter_probe.stack_alignment = 0
        self.getter_probe.home_space_written = 0
        self.getter_probe.stack_pointer = 0
        self.setter_probe.stack_alignment = 0
        self.setter_probe.home_space_written = 0
        self.setter_probe.stack_pointer = 0
        ctypes.memset(self.capacity_pointer, 0, 0x38)
        struct.pack_into("<I", self.capacity_node, 0x30, INITIAL_VALUE_TYPE)
        marker = ctypes.c_uint64(ROOT_MARKER)
        self.expected_marker_pointer = ctypes.addressof(marker)
        self.root_slot_pointer = 0
        operation = ctypes.create_string_buffer(0x180)
        returned_context = ctypes.c_uint64(0x123456789ABCDEF0)
        self.expected_return = ctypes.addressof(returned_context)
        struct.pack_into("<I", operation, 0x170, mode_id)
        struct.pack_into("<Q", operation, 0xE0, self.expected_return)
        self.operation_before = operation.raw
        self.result = self.function(ctypes.addressof(operation), self.expected_marker_pointer)
        self.operation_after = operation.raw
        self.marker = marker
        self.operation = operation
        self.returned_context = returned_context
        return self.result

    def close(self):
        if self.address is not None:
            if not self.kernel.VirtualFree(self.address, 0, 0x8000):
                raise ctypes.WinError(ctypes.get_last_error())
            self.address = None


class TestRequestPatchLayout(unittest.TestCase):
    def test_string_override_builder_preserves_numeric_default_and_uses_longer_stub(self):
        default_stub = patcher.build_request_stub()
        explicit_numeric_stub = patcher.build_request_stub(string_override=False)
        string_stub = patcher.build_request_stub(string_override=True)

        self.assertEqual(default_stub, explicit_numeric_stub)
        self.assertEqual(len(default_stub), 103)
        self.assertEqual(len(string_stub), 135)
        string_probes = patcher.patched_code_probes(string_override=True)
        self.assertEqual(string_probes[patcher.REQUEST_STRING_RVA], b"4\0")
        self.assertEqual(string_probes[patcher.STRING_REQUEST_UNWIND_RVA], patcher.REQUEST_UNWIND_INFO)
        self.assertIn(patcher.JSON_UTF8_SET_RVA, string_probes)
        self.assertIn(0x22F14B, string_probes)
        self.assertEqual(get_variant("request-number").sha256, NUMERIC_REQUEST_SHA256)

    def test_stub_reserves_call_space_and_restores_the_original_rcx(self):
        stub = patcher.build_request_stub()

        self.assertEqual(len(stub), 103)
        self.assertEqual(stub[:4], bytes.fromhex("4883ec28"))
        self.assertEqual(stub[-12:], bytes.fromhex("498b8ee00000004883c428c3"))
        self.assertIn(bytes.fromhex("4181be70010000") + struct.pack("<I", CAMPAIGN_MODE_ID), stub)
        self.assertIn(bytes.fromhex("4181be70010000") + struct.pack("<I", OPERATION_MODE_ID), stub)
        self.assertIn(bytes.fromhex("4181be70010000") + struct.pack("<I", INSIDE_THE_MIND_MODE_ID), stub)

    def test_request_probes_include_hook_stub_unwind_and_directory_growth(self):
        probes = patcher.patched_code_probes()

        expected_hook = b"\xe8" + struct.pack(
            "<i", patcher.REQUEST_STUB_RVA - patcher.REQUEST_HOOK_RVA - 5
        ) + b"\x90\x90"
        self.assertEqual(probes[patcher.REQUEST_HOOK_RVA], expected_hook)
        self.assertEqual(probes[patcher.REQUEST_STUB_RVA], patcher.build_request_stub())
        self.assertEqual(probes[patcher.REQUEST_UNWIND_RVA], patcher.REQUEST_UNWIND_INFO)
        self.assertEqual(
            probes[patcher.EXCEPTION_INSERT_RVA],
            struct.pack(
                "<III",
                patcher.REQUEST_STUB_RVA,
                patcher.REQUEST_STUB_RVA + len(patcher.build_request_stub()),
                patcher.REQUEST_UNWIND_RVA,
            ),
        )
        self.assertEqual(
            probes[STEAM.exception_directory_size_field],
            struct.pack("<I", STEAM.exception_table_size + 12),
        )
        self.assertNotIn(0xC9EAC0, probes)
        self.assertNotIn(0xC9EC60, probes)

    def test_numeric_probes_remain_the_default(self):
        self.assertEqual(patcher.patched_code_probes(), patcher.patched_code_probes(string_override=False))


class TestRuntimeFunctionInsertion(unittest.TestCase):
    def test_inserts_the_request_stub_entry_in_sorted_order(self):
        before = (patcher.REQUEST_STUB_RVA - 0x40, patcher.REQUEST_STUB_RVA - 0x20, 0x1E9F8100)
        after = (patcher.REQUEST_STUB_RVA + 0x200, patcher.REQUEST_STUB_RVA + 0x210, 0x1E9F8140)
        table = struct.pack("<III", *before) + struct.pack("<III", *after)
        expected = (
            before,
            (
                patcher.REQUEST_STUB_RVA,
                patcher.REQUEST_STUB_RVA + len(patcher.build_request_stub()),
                patcher.REQUEST_UNWIND_RVA,
            ),
            after,
        )

        actual = tuple(struct.iter_unpack("<III", patcher.add_runtime_function(table)))

        self.assertEqual(actual, expected)

    def test_string_request_entry_uses_the_string_stub_end(self):
        before = (patcher.REQUEST_STUB_RVA - 0x40, patcher.REQUEST_STUB_RVA - 0x20, 0x1E9F8100)
        table = struct.pack("<III", *before)

        actual = tuple(struct.iter_unpack("<III", patcher.add_runtime_function(table, string_override=True)))

        self.assertEqual(actual[1][0], patcher.REQUEST_STUB_RVA)
        self.assertEqual(actual[1][1], patcher.REQUEST_STUB_RVA + 135)
        self.assertEqual(actual[1][1] - actual[1][0], 135)
        self.assertEqual(actual[1][2], patcher.STRING_REQUEST_UNWIND_RVA)

    def test_rejects_a_malformed_runtime_function_table(self):
        with self.assertRaisesRegex(ValueError, "multiple of twelve"):
            patcher.add_runtime_function(b"\x00")

    def test_rejects_an_unsorted_runtime_function_table(self):
        later = (0x2000, 0x2010, 0x3000)
        earlier = (0x1000, 0x1010, 0x3010)
        table = struct.pack("<III", *later) + struct.pack("<III", *earlier)

        with self.assertRaisesRegex(ValueError, "not sorted"):
            patcher.add_runtime_function(table)

    def test_rejects_an_invalid_existing_function_range(self):
        invalid = (0x1000, 0x1000, 0x3000)

        with self.assertRaisesRegex(ValueError, "range is invalid"):
            patcher.add_runtime_function(struct.pack("<III", *invalid))

    def test_rejects_an_existing_function_that_overlaps_the_request_stub(self):
        overlapping = (
            patcher.REQUEST_STUB_RVA - 4,
            patcher.REQUEST_STUB_RVA + 4,
            0x1E9F8140,
        )

        with self.assertRaisesRegex(ValueError, "overlaps"):
            patcher.add_runtime_function(struct.pack("<III", *overlapping))


def _edits_match_source(source: Path, edits: tuple[ByteEdit, ...]) -> bool:
    with source.open("rb") as stream:
        for edit in edits:
            stream.seek(edit.offset)
            if stream.read(len(edit.original)) != edit.original:
                return False
    return True


def _preserves_dlc_edits(edits: tuple[ByteEdit, ...]) -> bool:
    actual = {edit.offset: edit for edit in edits}
    return all(actual.get(edit.offset) == edit for edit in capacity.build_edits("coop-dlc"))


@unittest.skipUnless(ORIGINAL_DLL, "Set FC6_ORIGINAL_DLL to a pristine FC6 DLL")
class TestRequestPatchEdits(unittest.TestCase):
    def test_edits_are_sorted_source_verified_and_preserve_the_dlc_profile(self):
        edits = get_variant("request-number").edits(ORIGINAL_DLL)
        offsets = tuple(edit.offset for edit in edits)
        by_offset = {edit.offset: edit for edit in edits}
        probes = patcher.patched_code_probes()

        self.assertEqual(offsets, tuple(sorted(offsets)))
        self.assertEqual(len(offsets), len(set(offsets)))
        self.assertEqual(patcher.build_edits(ORIGINAL_DLL), patcher.build_edits(ORIGINAL_DLL, string_override=False))
        self.assertTrue(_edits_match_source(ORIGINAL_DLL, edits))
        self.assertTrue(_preserves_dlc_edits(edits))
        hook_offset = file_offset(patcher.REQUEST_HOOK_RVA)
        self.assertEqual(hook_offset, 0xC75FAF)
        self.assertEqual(by_offset[hook_offset].original, bytes.fromhex("498b8ee0000000"))
        self.assertEqual(by_offset[hook_offset].replacement, probes[patcher.REQUEST_HOOK_RVA])

    def test_string_request_edits_preserve_dlc_hooks_and_embed_the_literal(self):
        edits = get_variant("request-string").edits(ORIGINAL_DLL)
        by_offset = {edit.offset: edit for edit in edits}
        stub_offset = file_offset(patcher.REQUEST_STUB_RVA)
        literal_offset = file_offset(patcher.REQUEST_STRING_RVA)
        unwind_offset = file_offset(patcher.STRING_REQUEST_UNWIND_RVA)

        self.assertEqual(tuple(edit.offset for edit in edits), tuple(sorted(by_offset)))
        self.assertTrue(_edits_match_source(ORIGINAL_DLL, edits))
        self.assertTrue(_preserves_dlc_edits(edits))
        self.assertEqual(by_offset[stub_offset].replacement, patcher.build_request_stub(string_override=True))
        self.assertEqual(by_offset[literal_offset].replacement, b"4\0")
        self.assertEqual(by_offset[unwind_offset].replacement, patcher.REQUEST_UNWIND_INFO)


class RequestHookModeContract:
    mode_id = 0

    def setUp(self):
        self.hook = NativeRequestHook()
        self.addCleanup(self.hook.close)

    def test_requests_four_and_restores_original_context(self):
        result = self.hook.invoke(self.mode_id)

        self.assertEqual(result, self.hook.expected_return)
        self.assertEqual(
            self.hook.get_calls,
            [
                (self.hook.root_slot_pointer, b"overrides"),
                (self.hook.overrides_pointer, b"maxTeamSize"),
            ],
        )
        self.assertEqual(self.hook.set_calls, [(self.hook.capacity_pointer, 4)])
        self.assertEqual(self.hook.root_markers_valid, [True])
        self.assertEqual(self.hook.overrides_markers_valid, [True])
        self.assertEqual(self.hook.unexpected_keys, [])
        self.assertEqual(self.hook.operation_after, self.hook.operation_before)
        self.assertEqual(self.hook.getter_probe.stack_alignment, 8)
        self.assertEqual(self.hook.setter_probe.stack_alignment, 8)
        self.assertEqual(self.hook.getter_probe.home_space_written, 1)
        self.assertEqual(self.hook.setter_probe.home_space_written, 1)


class UnmatchedRequestHookContract:
    mode_id = 0

    def setUp(self):
        self.hook = NativeRequestHook()
        self.addCleanup(self.hook.close)

    def test_leaves_unlisted_mode_and_request_objects_unchanged(self):
        result = self.hook.invoke(self.mode_id)

        self.assertEqual(result, self.hook.expected_return)
        self.assertEqual(self.hook.get_calls, [])
        self.assertEqual(self.hook.set_calls, [])
        self.assertEqual(self.hook.operation_after, self.hook.operation_before)


class StringRequestHookContract:
    mode_id = 0

    def setUp(self):
        self.hook = NativeRequestHook(string_override=True)
        self.addCleanup(self.hook.close)

    def test_sets_string_four_and_marks_json_value_as_string(self):
        result = self.hook.invoke(self.mode_id)

        self.assertEqual(result, self.hook.expected_return)
        self.assertEqual(
            self.hook.get_calls,
            [
                (self.hook.root_slot_pointer, b"overrides"),
                (self.hook.overrides_pointer, b"maxTeamSize"),
            ],
        )
        self.assertEqual(self.hook.set_calls, [(self.hook.capacity_pointer + 0x20, b"4")])
        self.assertEqual(struct.unpack_from("<I", self.hook.capacity_node, 0x30)[0], 0)
        self.assertEqual(self.hook.root_markers_valid, [True])
        self.assertEqual(self.hook.overrides_markers_valid, [True])
        self.assertEqual(self.hook.getter_probe.stack_alignment, 8)
        self.assertEqual(self.hook.setter_probe.stack_alignment, 8)
        self.assertEqual(self.hook.getter_probe.home_space_written, 1)
        self.assertEqual(self.hook.setter_probe.home_space_written, 1)


class UnmatchedStringRequestHookContract:
    mode_id = 0

    def setUp(self):
        self.hook = NativeRequestHook(string_override=True)
        self.addCleanup(self.hook.close)

    def test_leaves_unlisted_mode_type_and_request_objects_unchanged(self):
        result = self.hook.invoke(self.mode_id)

        self.assertEqual(result, self.hook.expected_return)
        self.assertEqual(self.hook.get_calls, [])
        self.assertEqual(self.hook.set_calls, [])
        self.assertEqual(struct.unpack_from("<I", self.hook.capacity_node, 0x30)[0], INITIAL_VALUE_TYPE)
        self.assertEqual(self.hook.operation_after, self.hook.operation_before)


class JsonNullStringRequestHookContract:
    def setUp(self):
        self.hook = NativeRequestHook(string_override=True, return_json_null=True)
        self.addCleanup(self.hook.close)

    def test_does_not_write_capacity_when_json_value_is_null(self):
        result = self.hook.invoke(CAMPAIGN_MODE_ID)

        self.assertEqual(result, self.hook.expected_return)
        self.assertEqual(
            self.hook.get_calls,
            [
                (self.hook.root_slot_pointer, b"overrides"),
                (self.hook.overrides_pointer, b"maxTeamSize"),
            ],
        )
        self.assertEqual(self.hook.set_calls, [])
        self.assertEqual(struct.unpack_from("<I", self.hook.capacity_node, 0x30)[0], INITIAL_VALUE_TYPE)
        self.assertEqual(self.hook.root_markers_valid, [True])
        self.assertEqual(self.hook.overrides_markers_valid, [True])
        self.assertEqual(self.hook.operation_after, self.hook.operation_before)


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestCampaignRequestHook(RequestHookModeContract, unittest.TestCase):
    mode_id = CAMPAIGN_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestOperationRequestHook(RequestHookModeContract, unittest.TestCase):
    mode_id = OPERATION_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestInsideTheMindRequestHook(RequestHookModeContract, unittest.TestCase):
    mode_id = INSIDE_THE_MIND_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestMainMenuRequestHook(UnmatchedRequestHookContract, unittest.TestCase):
    mode_id = MAIN_MENU_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestDlcY2RequestHook(UnmatchedRequestHookContract, unittest.TestCase):
    mode_id = DLC_Y2_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestStringCampaignRequestHook(StringRequestHookContract, unittest.TestCase):
    mode_id = CAMPAIGN_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestStringOperationRequestHook(StringRequestHookContract, unittest.TestCase):
    mode_id = OPERATION_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestStringInsideTheMindRequestHook(StringRequestHookContract, unittest.TestCase):
    mode_id = INSIDE_THE_MIND_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestUnmatchedStringRequestHook(UnmatchedStringRequestHookContract, unittest.TestCase):
    mode_id = MAIN_MENU_MODE_ID


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestJsonNullStringRequestHook(JsonNullStringRequestHookContract, unittest.TestCase):
    pass
