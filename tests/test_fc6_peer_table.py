import unittest

import capstone
from fc6_support import ORIGINAL_DLL

from fc6 import peer_table
from fc6.build import file_offset
from fc6.variants import get_variant


def decode(code: bytes, address: int):
    return list(capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64).disasm(code, address))


class TestPeerTableSites(unittest.TestCase):
    def test_every_site_changes_one_immediate_and_keeps_instruction_length(self):
        for rva, original, patched, _ in peer_table.SITES:
            with self.subTest(hex(rva)):
                before, after = decode(original, rva), decode(patched, rva)

                self.assertEqual(len(before), 1)
                self.assertEqual(len(after), 1)
                self.assertEqual((before[0].size, before[0].mnemonic), (after[0].size, after[0].mnemonic))
                self.assertEqual(sum(a != b for a, b in zip(original, patched)), 1)

    def test_peer_limits_are_consistent(self):
        text = {rva: decode(patched, rva)[0].op_str for rva, _, patched, _ in peer_table.SITES}

        self.assertEqual(text[0xCD1C1F], "r8d, [rsi + 4]")         # four table entries
        self.assertEqual(text[0xBFC5DFA], "edx, 3")               # highest id for sends, ja fails
        self.assertEqual(text[0xD4F854], "ecx, 4")                 # ids below four, jb succeeds
        self.assertEqual(text[0xD508F1], "r15d, 4")
        self.assertEqual(text[0xD4F29A], "dword ptr [r8 + 0x38], 4")

    def test_variant_extends_storm_peers(self):
        self.assertEqual(get_variant("peer-table").components[:-1], get_variant("storm-peers").components)
        self.assertEqual(get_variant("peer-owner").components[:-1], get_variant("peer-table").components)

    def test_owner_checks_only_raise_the_peer_limit(self):
        for rva, original, patched, _ in peer_table.OWNER_SITES:
            with self.subTest(hex(rva)):
                before, after = decode(original, rva)[0], decode(patched, rva)[0]

                self.assertEqual((before.mnemonic, before.size), ("cmp", after.size))
                self.assertTrue(before.op_str.endswith(", 2"))
                self.assertEqual(after.op_str, before.op_str[:-1] + "4")


@unittest.skipUnless(ORIGINAL_DLL, "Set FC6_ORIGINAL_DLL to a pristine FC6 DLL")
class TestPeerTableEvidence(unittest.TestCase):
    def read(self, rva, size):
        with ORIGINAL_DLL.open("rb") as stream:
            stream.seek(file_offset(rva, size))
            return stream.read(size)

    def disassemble(self, rva, size):
        return [f"{i.mnemonic} {i.op_str}" for i in decode(self.read(rva, size), rva)]

    def test_owner_checks_reject_with_object_ref_id_invalid_and_store_the_peer(self):
        for check, store in ((0xD45878, 0xD45892), (0xD45CDF, 0xD45D0F), (0xD45D6D, 0xD45D88)):
            with self.subTest(hex(check)):
                code = self.disassemble(check, 0x20)

                self.assertIn("mov dword ptr [rdx], 0xfff0bdfe", code)  # ObjectRefIdInvalid
        self.assertIn("mov dword ptr [rsi + 0x74], eax", self.disassemble(0xD45D0F, 0x30))
        self.assertEqual(self.disassemble(0xD45D88, 4), ["mov dword ptr [rcx + 0x74], eax"])

    def test_original_bytes(self):
        for rva, original, _, _ in peer_table.SITES + peer_table.OWNER_SITES:
            with self.subTest(hex(rva)):
                self.assertEqual(self.read(rva, len(original)), original)

    def test_constructor_builds_a_two_entry_inline_table_at_0x60(self):
        code = self.disassemble(0xCD1BF4, 0x40)

        self.assertIn("lea rcx, [r14 + 0x60]", code)
        self.assertIn("movabs rdx, 0x8000000080000002", code)   # inline capacity two
        self.assertIn("lea r8d, [rsi + 2]", code)

    def test_send_checks_the_same_table(self):
        code = self.disassemble(0xBFC5DFA, 0x11)

        self.assertEqual(code[:5], ["cmp edx, 1", "ja 0xbfc5e50", "mov rax, qword ptr [r8 + 0x60]",
                                    "mov ecx, edx", "cmp dword ptr [rax + rcx*4], 0"])

    def test_replica_handlers_write_the_table_through_the_second_interface(self):
        # The handlers run with this = object + 0x30, so their +0x30 is the object's +0x60 table
        self.assertIn("mov dword ptr [rax + rcx*4], 1", self.disassemble(0xD4F867, 0x1B))
        self.assertIn("mov dword ptr [rcx], 2", self.disassemble(0xD50905, 6))
        self.assertIn("mov dword ptr [rax + rcx*4], esi", self.disassemble(0xD4F2B5, 0x1E))


if __name__ == "__main__":
    unittest.main()
