import unittest

from fc6_support import ORIGINAL_DLL

from fc6 import storm_peers
from fc6.build import IMAGE_SIZE, TEXT1
from fc6.variants import RECOMMENDED, VARIANTS, get_variant, identify, patched_sha256


TEXT1_VIRTUAL_SIZES = {
    "campaign": 0x57,
    "coop-dlc": 0x89,
    "request-number": 0x128,
    "request-string": 0x152,
    "storm-peers": 0x152,
    "peer-table": 0x152,
    "peer-owner": 0x152,
}


class TestVariantRegistry(unittest.TestCase):
    def test_hashes_are_unique_and_identify_their_variant(self):
        hashes = [variant.sha256 for variant in VARIANTS.values()]

        self.assertEqual(len(hashes), len(set(hashes)))
        for variant in VARIANTS.values():
            self.assertIs(identify(variant.sha256), variant)
        self.assertIsNone(identify("0" * 64))

    def test_recommended_variant_includes_every_working_component(self):
        names = [component.name for component in get_variant(RECOMMENDED).components]

        self.assertEqual(RECOMMENDED, "peer-owner")
        self.assertEqual(names, ["co-op DLC capacity", "string sessions request", "Storm peer limit",
                                 "P2P peer table", "P2P object owner peer"])

    def test_rejects_unknown_variant(self):
        with self.assertRaisesRegex(ValueError, "Unknown variant"):
            get_variant("all-modes")

    def test_text1_growth_fits_the_raw_section_padding(self):
        for name, expected in TEXT1_VIRTUAL_SIZES.items():
            with self.subTest(name):
                actual = get_variant(name).text1_virtual_size()

                self.assertEqual(actual, expected)
                self.assertLessEqual(actual, TEXT1.raw_size)

    def test_component_probes_agree_and_stay_inside_the_image(self):
        for variant in VARIANTS.values():
            with self.subTest(variant.name):
                probes = variant.probes()

                self.assertTrue(all(rva + len(code) <= IMAGE_SIZE for rva, code in probes.items()))

    def test_storm_variant_keeps_every_request_string_probe(self):
        storm, previous = get_variant("storm-peers").probes(), get_variant("request-string").probes()

        self.assertEqual({rva: code for rva, code in storm.items() if rva in previous}, previous)
        self.assertEqual(storm[storm_peers.BLOCK_RVA], storm_peers.patched_block())

    def test_storm_variant_adds_one_region_to_request_string(self):
        storm = get_variant("storm-peers").components
        request = get_variant("request-string").components

        self.assertEqual(storm[:-1], request)


@unittest.skipUnless(ORIGINAL_DLL, "Set FC6_ORIGINAL_DLL to a pristine FC6 DLL")
class TestVariantBuilds(unittest.TestCase):
    def test_every_variant_reproduces_its_pinned_hash(self):
        for variant in VARIANTS.values():
            with self.subTest(variant.name):
                self.assertEqual(patched_sha256(ORIGINAL_DLL, variant.edits(ORIGINAL_DLL)), variant.sha256)

    def test_modified_byte_counts_match_the_published_notes(self):
        expected = {"campaign": 68, "coop-dlc": 104, "request-number": 4568,
                    "request-string": 4597, "storm-peers": 4602,
                    "peer-table": 4607, "peer-owner": 4610}
        for name, count in expected.items():
            with self.subTest(name):
                edits = get_variant(name).edits(ORIGINAL_DLL)

                self.assertEqual(sum(a != b for e in edits for a, b in zip(e.original, e.replacement)), count)


if __name__ == "__main__":
    unittest.main()
