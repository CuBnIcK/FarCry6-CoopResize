import struct
import unittest

from fc6_support import NATIVE_X64
from test_fc6_capacity_patch import NativeHook

from fc6 import capacity as patcher
from fc6.variants import get_variant


class DlcCapacityHookContract:
    def setUp(self):
        self.hook = NativeHook(self.source_register, profile="coop-dlc")
        self.addCleanup(self.hook.close)

    def test_expands_campaign_two_to_four(self):
        result, destination, _, _ = self.hook.invoke(0x6A3C926F, 2)

        self.assertEqual(result, 4)
        self.assertEqual(destination[0x39], 4)

    def test_expands_inside_the_mind_two_to_four(self):
        result, destination, _, _ = self.hook.invoke(0xDA8F2C61, 2)

        self.assertEqual(result, 4)
        self.assertEqual(destination[0x39], 4)

    def test_expands_special_operation_two_to_four(self):
        result, destination, _, _ = self.hook.invoke(0x9B7024CE, 2)

        self.assertEqual(result, 4)
        self.assertEqual(destination[0x39], 4)

    def test_preserves_unconfirmed_defence_mode(self):
        result, destination, _, _ = self.hook.invoke(0x5EDADEB8, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_main_menu_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x83AE70EF, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_benchmark_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x91C0A124, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_never_targets_pvp_mode(self):
        result, destination, _, _ = self.hook.invoke(0x5F20EC1A, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_dlcy2_single_player_capacity(self):
        result, destination, _, _ = self.hook.invoke(0x6BE16A15, 1)

        self.assertEqual(result, 1)
        self.assertEqual(destination[0x39], 1)

    def test_never_targets_dlcy2_even_with_capacity_two(self):
        result, destination, _, _ = self.hook.invoke(0x6BE16A15, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_unknown_mode(self):
        result, destination, _, _ = self.hook.invoke(0xFFFFFFFF, 2)

        self.assertEqual(result, 2)
        self.assertEqual(destination[0x39], 2)

    def test_preserves_explicit_single_player_dlc_capacity(self):
        result, destination, _, _ = self.hook.invoke(0xDA8F2C61, 1)

        self.assertEqual(result, 1)
        self.assertEqual(destination[0x39], 1)

    def test_preserves_already_expanded_dlc_capacity(self):
        result, destination, _, _ = self.hook.invoke(0xDA8F2C61, 4)

        self.assertEqual(result, 4)
        self.assertEqual(destination[0x39], 4)

    def test_preserves_zero_dlc_capacity(self):
        result, destination, _, _ = self.hook.invoke(0xDA8F2C61, 0)

        self.assertEqual(result, 0)
        self.assertEqual(destination[0x39], 0)

    def test_preserves_maximum_byte_dlc_capacity(self):
        result, destination, _, _ = self.hook.invoke(0xDA8F2C61, 255)

        self.assertEqual(result, 255)
        self.assertEqual(destination[0x39], 255)

    def test_preserves_source_record(self):
        _, _, actual, expected = self.hook.invoke(0xDA8F2C61, 2)

        self.assertEqual(actual, expected)

    def test_writes_only_dlc_destination_capacity(self):
        expected = bytearray(b"\x5a" * 0x78)
        expected[0x39] = 4

        _, destination, _, _ = self.hook.invoke(0xDA8F2C61, 2)

        self.assertEqual(destination, bytes(expected))


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestDlcRdiSourceHook(DlcCapacityHookContract, unittest.TestCase):
    source_register = "rdi"


@unittest.skipUnless(NATIVE_X64, "Windows x64 native test")
class TestDlcRbxSourceHook(DlcCapacityHookContract, unittest.TestCase):
    source_register = "rbx"


class TestDlcProfileLayout(unittest.TestCase):
    def test_profile_has_six_ordered_regions(self):
        edits = get_variant("coop-dlc").edits(None)

        self.assertEqual(len(edits), 6)
        self.assertEqual(tuple(e.offset for e in edits), tuple(sorted(e.offset for e in edits)))

    def test_profile_extends_existing_section_only_to_its_hooks(self):
        edit = get_variant("coop-dlc").edits(None)[0]

        self.assertEqual(edit.offset, 0x330)
        self.assertEqual(edit.original, struct.pack("<I", 9))
        self.assertEqual(edit.replacement, struct.pack("<I", 0x89))

    def test_profile_uses_two_separate_41_byte_hooks(self):
        probes = patcher.patched_code_probes("coop-dlc")

        self.assertEqual(len(probes[0x1E9F8020]), 41)
        self.assertEqual(len(probes[0x1E9F8060]), 41)

    def test_original_campaign_hook_is_byte_identical(self):
        actual = patcher.build_capacity_stub("rdi")

        self.assertEqual(actual, bytes.fromhex("0fb64739817f186f923c6a75063c027502b004884339c3"))

    def test_rejects_unknown_profile(self):
        with self.assertRaisesRegex(ValueError, "profile"):
            patcher.build_edits("all-modes")


if __name__ == "__main__":
    unittest.main()
