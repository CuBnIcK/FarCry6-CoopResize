import ctypes
import struct
import unittest

import capstone
from fc6_support import NATIVE_X64, ORIGINAL_DLL

from fc6 import storm_peers
from fc6.build import file_offset


BLOCK_START = storm_peers.BLOCK_RVA
BLOCK_END = BLOCK_START + len(storm_peers.ORIGINAL_BLOCK)
CODE_SIZE = 0x1000
NOTIFY_OFFSET = 0x200
RETURN_OFFSET = 0x280
STORM_CONFIG_DEFAULT_MAX_PEERS = 0x80


def decode(block: bytes) -> list:
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = True
    return list(disassembler.disasm(block, BLOCK_START))


class TestStormPeerBlock(unittest.TestCase):
    def test_original_block_sets_both_properties_to_two(self):
        text = [f"{i.mnemonic} {i.op_str}" for i in decode(storm_peers.ORIGINAL_BLOCK)]

        self.assertEqual(text[0], "cmp dword ptr [rbx + 0x18], 2")
        self.assertIn("mov dword ptr [rbx + 0x18], 2", text)
        self.assertIn("cmp dword ptr [r15 + 0x158], 2", text)
        self.assertIn("lea rbx, [r15 + 0x160]", text)
        self.assertEqual(text[-1], "mov dword ptr [rbx + 0x18], 2")
        self.assertEqual(sum(i.endswith(", 2") for i in text), 5)

    def test_patch_changes_only_the_five_immediates(self):
        original, patched = storm_peers.ORIGINAL_BLOCK, storm_peers.patched_block()
        changed = [index for index, (a, b) in enumerate(zip(original, patched)) if a != b]

        self.assertEqual(len(patched), len(original))
        self.assertEqual(changed, list(storm_peers.IMMEDIATE_OFFSETS))
        self.assertTrue(all(patched[index] == 4 for index in changed))

    def test_patch_keeps_instruction_boundaries_and_branch_targets(self):
        before, after = decode(storm_peers.ORIGINAL_BLOCK), decode(storm_peers.patched_block())

        self.assertEqual([(i.address, i.size, i.mnemonic) for i in before],
                         [(i.address, i.size, i.mnemonic) for i in after])
        self.assertEqual(sum(i.size for i in after), len(storm_peers.ORIGINAL_BLOCK))
        for old, new in zip(before, after):
            if old.mnemonic.startswith("j") or old.mnemonic == "call":
                self.assertEqual(old.op_str, new.op_str)
            else:
                self.assertEqual(old.op_str.replace(", 2", ", 4"), new.op_str)

    def test_conditional_branches_stay_inside_the_block(self):
        for instruction in decode(storm_peers.patched_block()):
            if instruction.mnemonic in ("je", "ja"):
                self.assertTrue(BLOCK_START < int(instruction.op_str, 16) <= BLOCK_END)

    def test_rejects_limits_outside_the_signed_imm8_range(self):
        for peers in (0, 0x80):
            with self.subTest(peers):
                with self.assertRaises(ValueError):
                    storm_peers.patched_block(peers)

    def test_maps_into_the_xtls_code_section(self):
        self.assertEqual(file_offset(BLOCK_START), 0xCD22F6)
        self.assertEqual(storm_peers.build_edits()[0].offset, 0xCD22F6)


@unittest.skipUnless(ORIGINAL_DLL, "Set FC6_ORIGINAL_DLL to a pristine FC6 DLL")
class TestStormPeerEvidence(unittest.TestCase):
    """Static facts in the original DLL that tie the patched block to Storm maxPeers."""

    def read(self, rva, size):
        with ORIGINAL_DLL.open("rb") as stream:
            stream.seek(file_offset(rva, size))
            return stream.read(size)

    def test_original_file_contains_the_block(self):
        self.assertEqual(self.read(BLOCK_START, len(storm_peers.ORIGINAL_BLOCK)), storm_peers.ORIGINAL_BLOCK)

    def test_block_belongs_to_the_session_constructor_before_slot_setup(self):
        # lea rbx, [r15+0x140] just before, call of the slot and team setup thunk 0xd27580 just after
        self.assertEqual(self.read(0xCD2CBC, 7), bytes.fromhex("498d9f40010000"))
        self.assertEqual(self.read(BLOCK_END, 8), bytes.fromhex("498bcfe817480500"))

    def test_storm_config_serializer_names_the_patched_fields(self):
        # config +0x110 is written as "maxPeers" and +0x130 as "maxPeersId", Session+0x48 is the config
        self.assertEqual(self.read(0x4EC42C7, 7), bytes.fromhex("448b9510010000"))
        self.assertEqual(self.read(0x4EC432E, 7), bytes.fromhex("448b9530010000"))
        self.assertEqual(self.read(0xBE61937, 4), bytes.fromhex("4883c048"))

    def test_storm_config_default_is_128_peers(self):
        self.assertEqual(self.read(0xCD736B, 7), bytes.fromhex("c7431880000000"))


class NativeStormBlock:
    """Run the constructor block on a fake session, with the property notify call stubbed."""

    def __init__(self, block: bytes):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
        kernel.VirtualAlloc.restype = ctypes.c_void_p
        kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        kernel.VirtualProtect.restype = ctypes.c_int
        kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        kernel.VirtualFree.restype = ctypes.c_int
        self.kernel = kernel
        self.notify_count = ctypes.c_uint32()
        self.address = kernel.VirtualAlloc(None, CODE_SIZE, 0x3000, 0x04)
        if not self.address:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self._install(block)
        except BaseException:
            kernel.VirtualFree(self.address, 0, 0x8000)
            raise

    def _install(self, block: bytes):
        prefix = bytes.fromhex("5341574883ec28" "4989cf" "498d9f40010000")
        suffix = bytes.fromhex("4883c42841" "5f5bc3")
        code = bytearray(prefix + block + suffix)
        for instruction in decode(block):
            if instruction.mnemonic == "call" and instruction.op_str.startswith("0x"):
                # Never reached while notify returns zero, but point it at a ret anyway
                offset = len(prefix) + instruction.address - BLOCK_START
                struct.pack_into("<i", code, offset + 1, RETURN_OFFSET - (offset + 5))
        notify = b"\x48\xb8" + struct.pack("<Q", ctypes.addressof(self.notify_count)) + bytes.fromhex("ff0031c0c3")
        image = bytearray(b"\xcc" * CODE_SIZE)
        image[:len(code)] = code
        image[NOTIFY_OFFSET:NOTIFY_OFFSET + len(notify)] = notify
        image[RETURN_OFFSET] = 0xC3
        ctypes.memmove(self.address, bytes(image), len(image))
        old = ctypes.c_ulong()
        if not self.kernel.VirtualProtect(self.address, CODE_SIZE, 0x20, ctypes.byref(old)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.function = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self.address)
        self.vtable = (ctypes.c_uint64 * 8)(*([self.address + NOTIFY_OFFSET] * 8))

    def run(self, max_peers: int, max_peers_id: int) -> tuple[int, int, bytes, int]:
        session = ctypes.create_string_buffer(0x200)
        dirty = (ctypes.c_uint8 * 2)()
        for index, (offset, value) in enumerate(((0x140, max_peers), (0x160, max_peers_id))):
            struct.pack_into("<QQ", session, offset, ctypes.addressof(self.vtable), ctypes.addressof(dirty) + index)
            struct.pack_into("<I", session, offset + 0x18, value)
        self.notify_count.value = 0
        self.function(ctypes.addressof(session))
        peers, peers_id = struct.unpack_from("<I", session, 0x158)[0], struct.unpack_from("<I", session, 0x178)[0]
        return peers, peers_id, bytes(dirty), self.notify_count.value

    def close(self):
        if not self.kernel.VirtualFree(self.address, 0, 0x8000):
            raise ctypes.WinError(ctypes.get_last_error())


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestNativeStormBlock(unittest.TestCase):
    def execute(self, block, max_peers=STORM_CONFIG_DEFAULT_MAX_PEERS, max_peers_id=0):
        native = NativeStormBlock(block)
        self.addCleanup(native.close)
        return native.run(max_peers, max_peers_id)

    def test_original_constructor_limits_storm_to_two_peers(self):
        self.assertEqual(self.execute(storm_peers.ORIGINAL_BLOCK), (2, 2, b"\x01\x01", 2))

    def test_patched_constructor_allows_four_peers(self):
        self.assertEqual(self.execute(storm_peers.patched_block()), (4, 4, b"\x01\x01", 2))

    def test_patched_constructor_keeps_matching_values_untouched(self):
        self.assertEqual(self.execute(storm_peers.patched_block(), 4, 4), (4, 4, b"\x00\x00", 0))

    def test_patched_max_peers_id_satisfies_storm_create_check(self):
        # storm create fails with 0xfff0bdd3 when maxPeersId is nonzero and below maxPeers
        peers, peers_id, _, _ = self.execute(storm_peers.patched_block())

        self.assertTrue(peers_id == 0 or peers <= peers_id)


if __name__ == "__main__":
    unittest.main()
