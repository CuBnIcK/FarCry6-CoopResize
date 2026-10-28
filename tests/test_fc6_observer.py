import hashlib
import io
import struct
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fc6_support import MemoryImage

from fc6 import capacity, session_request, storm_peers
from fc6 import runtime as observer
from fc6.build import IMAGE_SIZE
from fc6.variants import VARIANTS, Variant, get_variant


class TestFC6SessionObservation(unittest.TestCase):
    def setUp(self):
        self.memory = MemoryImage()
        self.base = 0x180000000
        self.manager = 0x10000000
        self.table = 0x20000000
        self.session = 0x30000000
        self.global_address = self.base + 0x6B68D80
        self.memory.regions[self.global_address] = bytearray(struct.pack("<Q", self.manager))
        self.manager_data = bytearray(0x120)
        struct.pack_into("<QQ", self.manager_data, 0xC8, self.table, 1 << 32)
        self.memory.regions[self.manager] = self.manager_data
        self.memory.regions[self.table] = bytearray(struct.pack("<IIQ", 7, 0, self.session))
        self.session_data = bytearray(0x4B0)
        struct.pack_into("<Q", self.session_data, 0, self.base + 0x58E8A08)
        struct.pack_into("<I", self.session_data, 0x4AC, 7)
        self.session_data[0x3E0:0x3E3] = bytes([2, 0, 2])
        self.session_data[0x439:0x43B] = bytes([2, 1])
        struct.pack_into("<II", self.session_data, 0x158, 2, 0)
        struct.pack_into("<I", self.session_data, 0x178, 2)
        self.memory.regions[self.session] = self.session_data

    def sample(self):
        return observer.sample_sessions(self.memory.read, self.base)["sessions"][0]

    def test_reports_full_two_player_session(self):
        session = self.sample()

        self.assertEqual(session["session_id"], 7)
        self.assertEqual(session["max_slots"], 2)
        self.assertEqual(session["available_slots"], 0)
        self.assertEqual(session["team_record_count"], 1)
        self.assertTrue(session["consistent"])
        self.assertTrue(session["storm_allows_max_slots"])

    def test_reports_storm_limit_below_game_slots(self):
        self.session_data[0x3E0:0x3E3] = bytes([2, 0, 4])
        self.session_data[0x439] = 4

        session = self.sample()

        self.assertEqual((session["storm_max_peers"], session["storm_max_peers_id"]), (2, 2))
        self.assertTrue(session["consistent"])
        self.assertFalse(session["storm_allows_max_slots"])

    def test_accepts_storm_limit_matching_four_game_slots(self):
        self.session_data[0x3E0:0x3E3] = bytes([2, 0, 4])
        self.session_data[0x439] = 4
        struct.pack_into("<I", self.session_data, 0x158, 4)
        struct.pack_into("<I", self.session_data, 0x178, 4)

        session = self.sample()

        self.assertEqual((session["storm_max_peers"], session["storm_max_peers_id"]), (4, 4))
        self.assertTrue(session["storm_allows_max_slots"])

    def test_subtracts_reservations_from_four_player_fixture(self):
        self.session_data[0x3E0:0x3E3] = bytes([2, 1, 4])
        self.session_data[0x439] = 4

        self.assertEqual(self.sample()["available_slots"], 1)

    def test_marks_descriptor_and_slot_disagreement(self):
        self.session_data[0x439] = 4

        self.assertFalse(self.sample()["consistent"])

    def test_reports_uninitialized_manager(self):
        self.memory.regions[self.global_address] = bytearray(8)

        result = observer.sample_sessions(self.memory.read, self.base)

        self.assertFalse(result["manager_initialized"])
        self.assertEqual(result["sessions"], [])

    def test_rejects_unreadable_global(self):
        self.memory.regions.pop(self.global_address)

        with self.assertRaisesRegex(RuntimeError, "Cannot read"):
            observer.sample_sessions(self.memory.read, self.base)

    def test_rejects_oversized_session_table(self):
        struct.pack_into("<Q", self.manager_data, 0xD0, 10000 << 32)

        with self.assertRaisesRegex(RuntimeError, "diagnostic limit"):
            observer.sample_sessions(self.memory.read, self.base)

    def test_rejects_null_table_with_nonzero_count(self):
        struct.pack_into("<Q", self.manager_data, 0xC8, 0)

        with self.assertRaisesRegex(RuntimeError, "null table"):
            observer.sample_sessions(self.memory.read, self.base)

    def test_rejects_another_object_type(self):
        struct.pack_into("<Q", self.session_data, 0, self.base + 0x1000)

        with self.assertRaisesRegex(RuntimeError, "vtable"):
            observer.sample_sessions(self.memory.read, self.base)

    def test_rejects_reused_session_pointer(self):
        struct.pack_into("<I", self.session_data, 0x4AC, 8)

        with self.assertRaisesRegex(RuntimeError, "session ID"):
            observer.sample_sessions(self.memory.read, self.base)

    def test_masks_the_vector_count_flag(self):
        struct.pack_into("<Q", self.manager_data, 0xD0, 0x80000001 << 32)

        result = observer.sample_sessions(self.memory.read, self.base)

        self.assertEqual(len(result["sessions"]), 1)

    def test_reads_the_secondary_session_table(self):
        struct.pack_into("<QQ", self.manager_data, 0xC8, 0, 0)
        struct.pack_into("<QQ", self.manager_data, 0x110, self.table, 1 << 32)

        self.assertEqual(self.sample()["table"], "secondary")

    def test_rejects_session_table_changed_during_read(self):
        reader = Mock(side_effect=[
            struct.pack("<Q", self.manager),
            struct.pack("<QQ", self.table, 1 << 32),
            bytes(self.memory.regions[self.table]),
            bytes(self.session_data),
            bytes(16),
        ])

        with self.assertRaisesRegex(RuntimeError, "collection changed"):
            observer.sample_sessions(reader, self.base)


class TestFC6ModuleIdentity(unittest.TestCase):
    base = 0x180000000

    def verify(self, variant_name, mutate=None):
        """Load a fixture file whose hash stands in for variant_name, then verify it."""
        fixture = f"{variant_name} fixture".encode()
        digest = hashlib.sha256(fixture).hexdigest()
        real = get_variant(variant_name)
        variants = {"fixture": Variant(real.name, digest, real.summary, real.components)}
        memory = MemoryImage()
        probes = observer.CODE_PROBES | real.probes()
        memory.regions = {self.base + rva: bytearray(value) for rva, value in probes.items()}
        if mutate:
            mutate(memory)
        with patch.object(Path, "open", return_value=io.BytesIO(fixture)):
            return observer.verify_module(memory.read, self.base, IMAGE_SIZE, Path("fixture.dll"), variants)

    def corrupt(self, rva):
        def mutate(memory):
            memory.regions[self.base + rva][0] ^= 0xFF
        return mutate

    def test_accepts_every_variant_with_matching_loaded_code(self):
        for name in VARIANTS:
            with self.subTest(name):
                self.assertEqual(self.verify(name).name, name)

    def test_rejects_changed_storm_peer_block(self):
        with self.assertRaisesRegex(RuntimeError, "differs at RVA 0xcd2cf6"):
            self.verify("storm-peers", self.corrupt(storm_peers.BLOCK_RVA))

    def test_rejects_changed_text1_virtual_size(self):
        with self.assertRaisesRegex(RuntimeError, "differs at RVA 0x330"):
            self.verify("storm-peers", self.corrupt(0x330))

    def test_rejects_changed_loaded_request_string_literal(self):
        with self.assertRaisesRegex(RuntimeError, "differs"):
            self.verify("request-string", self.corrupt(session_request.REQUEST_STRING_RVA))

    def test_rejects_changed_loaded_request_stub(self):
        with self.assertRaisesRegex(RuntimeError, "differs"):
            self.verify("request-number", self.corrupt(session_request.REQUEST_STUB_RVA))

    def test_rejects_changed_loaded_request_unwind_info(self):
        with self.assertRaisesRegex(RuntimeError, "differs"):
            self.verify("request-number", self.corrupt(session_request.REQUEST_UNWIND_RVA))

    def test_rejects_changed_loaded_dlc_hook(self):
        with self.assertRaisesRegex(RuntimeError, "differs"):
            self.verify("coop-dlc", self.corrupt(0x1E9F8060))

    def test_rejects_patched_file_when_runtime_hook_was_replaced(self):
        with self.assertRaisesRegex(RuntimeError, "differs"):
            self.verify("campaign", self.corrupt(capacity.PROFILES["campaign"].stub_rvas["rdi"]))

    def test_rejects_changed_original_join_check(self):
        with self.assertRaisesRegex(RuntimeError, "differs at RVA 0xd4274a"):
            self.verify("original", self.corrupt(0xD4274A))

    def test_rejects_wrong_module_size_before_reading_files(self):
        with self.assertRaisesRegex(RuntimeError, "module size"):
            observer.verify_module(Mock(), self.base, 0x1000, Path("fixture.dll"))

    def test_rejects_another_dll_hash(self):
        with patch.object(Path, "open", return_value=io.BytesIO(b"another build")):
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                observer.verify_module(Mock(), self.base, IMAGE_SIZE, Path("fixture.dll"))


if __name__ == "__main__":
    unittest.main()
