import ctypes
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from fc6_support import NATIVE_X64, SANDBOX_ROOT

from fc6 import capacity as patcher
from fc6.edits import ByteEdit, write_verified_copy
from fc6.variants import create_package, get_variant


class NativeHook:
    def __init__(self, source_register, profile="campaign"):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
        kernel.VirtualAlloc.restype = ctypes.c_void_p
        kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        kernel.VirtualProtect.restype = ctypes.c_int
        kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        kernel.VirtualFree.restype = ctypes.c_int
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        kernel.FlushInstructionCache.restype = ctypes.c_int
        self.kernel = kernel
        setup = {
            "rdi": bytes.fromhex("4889cf4889d3"),
            "rbx": bytes.fromhex("4889cb4889d7"),
        }[source_register]
        prefix = bytes.fromhex("53574883ec28") + setup
        call = b"\xe8" + struct.pack("<i", 32 - len(prefix) - 5)
        wrapper = prefix + call + bytes.fromhex("4883c4285f5bc3")
        code = wrapper.ljust(32, b"\x90") + patcher.build_capacity_stub(source_register, profile)
        self.address = kernel.VirtualAlloc(None, len(code), 0x3000, 0x04)
        if not self.address:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            ctypes.memmove(self.address, code, len(code))
            old_protection = ctypes.c_ulong()
            if not kernel.VirtualProtect(self.address, len(code), 0x20, ctypes.byref(old_protection)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not kernel.FlushInstructionCache(kernel.GetCurrentProcess(), self.address, len(code)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.function = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p)(self.address)
        except BaseException:
            kernel.VirtualFree(self.address, 0, 0x8000)
            raise

    def close(self):
        if not self.kernel.VirtualFree(self.address, 0, 0x8000):
            raise ctypes.WinError(ctypes.get_last_error())

    def invoke(self, mode_id, capacity):
        source = bytearray(b"\xa5" * 0x78)
        struct.pack_into("<I", source, 0x18, mode_id)
        source[0x38:0x3B] = bytes([1, capacity, 1])
        source_buffer = ctypes.create_string_buffer(bytes(source), len(source))
        destination = ctypes.create_string_buffer(b"\x5a" * 0x78, 0x78)
        result = self.function(ctypes.addressof(source_buffer), ctypes.addressof(destination))
        return result, destination.raw, source_buffer.raw, bytes(source)


class CapacityHookContract:
    def setUp(self):
        self.hook = NativeHook(self.source_register)
        self.addCleanup(self.hook.close)

    def test_expands_campaign_two_to_four(self):
        result, destination, _, _ = self.hook.invoke(0x6A3C926F, 2)

        self.assertEqual(result, 4)
        self.assertEqual(destination[0x39], 4)

    def test_preserves_two_for_other_modes(self):
        result, destination, _, _ = self.hook.invoke(0x83AE70EF, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_inside_the_mind_capacity(self):
        result, destination, _, _ = self.hook.invoke(0xDA8F2C61, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_dlcy2_single_player_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x6BE16A15, 1)

        self.assertEqual(result, 1)
        self.assertEqual(destination[0x39], 1)

    def test_preserves_operation_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x9B7024CE, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_defence_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x5EDADEB8, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_solo_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x6A3C926F, 1)

        self.assertEqual(result, 1)
        self.assertEqual(destination[0x39], 1)

    def test_preserves_already_expanded_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x6A3C926F, 4)

        self.assertEqual(result, 4)
        self.assertEqual(destination[0x39], 4)

    def test_preserves_zero_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x6A3C926F, 0)

        self.assertEqual(result, 0)
        self.assertEqual(destination[0x39], 0)

    def test_preserves_maximum_byte_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x6A3C926F, 255)

        self.assertEqual(result, 255)
        self.assertEqual(destination[0x39], 255)

    def test_does_not_change_source(self):
        _, _, actual_source, expected_source = self.hook.invoke(0x6A3C926F, 2)

        self.assertEqual(actual_source, expected_source)

    def test_writes_only_destination_capacity(self):
        expected = bytearray(b"\x5a" * 0x78)
        expected[0x39] = 4

        _, destination, _, _ = self.hook.invoke(0x6A3C926F, 2)

        self.assertEqual(destination, bytes(expected))


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestRdiSourceHook(CapacityHookContract, unittest.TestCase):
    source_register = "rdi"


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestRbxSourceHook(CapacityHookContract, unittest.TestCase):
    source_register = "rbx"


class TestFC6CopySafety(unittest.TestCase):
    def setUp(self):
        SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
        self.sandbox = tempfile.TemporaryDirectory(dir=SANDBOX_ROOT)
        self.addCleanup(self.sandbox.cleanup)
        self.directory = Path(self.sandbox.name)
        self.source = self.directory / "original.dll"
        self.source.write_bytes(b"abcdefgh")
        self.destination = self.directory / "patched.dll"

    def test_writes_verified_copy_without_changing_source(self):
        edits = (ByteEdit(2, b"cd", b"XY"),)
        expected = hashlib.sha256(b"abXYefgh").hexdigest()

        write_verified_copy(self.source, self.destination, edits, expected)

        self.assertEqual(self.destination.read_bytes(), b"abXYefgh")
        self.assertEqual(self.source.read_bytes(), b"abcdefgh")

    def test_preserves_existing_destination(self):
        self.destination.write_bytes(b"user data")

        with self.assertRaises(FileExistsError):
            write_verified_copy(self.source, self.destination, (), "wrong hash")

        self.assertEqual(self.destination.read_bytes(), b"user data")

    def test_refuses_source_as_destination(self):
        with self.assertRaises(FileExistsError):
            write_verified_copy(self.source, self.source, (), "wrong hash")

        self.assertEqual(self.source.read_bytes(), b"abcdefgh")

    def test_rejects_unexpected_original_bytes(self):
        edits = (ByteEdit(2, b"WR", b"XY"),)

        with self.assertRaisesRegex(ValueError, "Original bytes"):
            write_verified_copy(self.source, self.destination, edits, "unused")

        self.assertEqual(list(self.directory.iterdir()), [self.source])

    def test_rejects_unexpected_output_hash_without_partial_file(self):
        with self.assertRaisesRegex(ValueError, "Output SHA-256"):
            write_verified_copy(self.source, self.destination, (), "wrong hash")

        self.assertEqual(list(self.directory.iterdir()), [self.source])

    def test_rejects_another_build_before_creating_output_directory(self):
        output = self.directory / "package"

        with self.assertRaisesRegex(ValueError, "Source SHA-256"):
            create_package(self.source, output)

        self.assertFalse(output.exists())

    def test_rejects_overlapping_edits(self):
        edits = (ByteEdit(2, b"cd", b"XY"), ByteEdit(3, b"de", b"ZZ"))

        with self.assertRaisesRegex(ValueError, "overlap"):
            write_verified_copy(self.source, self.destination, edits, "unused")

        self.assertFalse(self.destination.exists())

    def test_rejects_size_changing_edits(self):
        edits = (ByteEdit(2, b"cd", b"XYZ"),)

        with self.assertRaisesRegex(ValueError, "length"):
            write_verified_copy(self.source, self.destination, edits, "unused")

        self.assertFalse(self.destination.exists())


class TestFC6PatchLayout(unittest.TestCase):
    def test_rejects_an_unknown_register_layout(self):
        with self.assertRaises(ValueError):
            patcher.build_capacity_stub("rax")

    def test_has_six_fixed_size_regions(self):
        edits = get_variant("campaign").edits(None)

        self.assertEqual(len(edits), 6)
        self.assertEqual(sum(len(e.original) for e in edits), sum(len(e.replacement) for e in edits))

    def test_extends_only_the_existing_section_virtual_size(self):
        edit = get_variant("campaign").edits(None)[0]

        self.assertEqual(edit.offset, 0x330)
        self.assertEqual(edit.original, struct.pack("<I", 9))
        self.assertEqual(edit.replacement, struct.pack("<I", 0x57))

    def test_copy_sites_keep_their_known_file_offsets(self):
        offsets = {edit.offset for edit in patcher.build_edits("campaign")}

        self.assertTrue({0xC54F7C, 0xC5B463, 0xAAE4C71} <= offsets)


if __name__ == "__main__":
    unittest.main()
