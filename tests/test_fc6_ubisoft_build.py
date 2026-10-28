import bisect
import re
import struct
import unittest

import capstone
from fc6_support import ORIGINAL_DLL, UBISOFT_DLL

from fc6 import session_request, storm_peers
from fc6.build import STEAM, UBISOFT, Build
from fc6.edits import file_sha256
from fc6.variants import RECOMMENDED, VARIANTS, get_variant, identify_any, patched_sha256


DISASSEMBLER = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
DISASSEMBLER.detail = True
DATA_STRINGS = {
    session_request.OVERRIDES_STRING_RVA: b"overrides\0",
    session_request.MAX_TEAM_SIZE_STRING_RVA: b"maxTeamSize\0",
}
DATA_RVAS = set(DATA_STRINGS) | {session_request.JSON_NULL_RVA}
# The UTF-8 setter is a leaf without a RUNTIME_FUNCTION, compare a fixed window instead
LEAF_WINDOWS = {session_request.JSON_UTF8_SET_RVA: 0x60}


class TestUbisoftRegistry(unittest.TestCase):
    def test_only_the_recommended_variant_is_published_for_ubisoft(self):
        published = [name for name, variant in VARIANTS.items() if variant.hash_for(UBISOFT)]

        self.assertEqual(published, ["original", RECOMMENDED])
        self.assertEqual(identify_any(UBISOFT.sha256), (VARIANTS["original"], UBISOFT))
        variant = get_variant(RECOMMENDED)
        self.assertEqual(identify_any(variant.hash_for(UBISOFT)), (variant, UBISOFT))

    def test_relocated_stubs_and_probes_stay_inside_the_image(self):
        probes = get_variant(RECOMMENDED).probes(UBISOFT)

        self.assertTrue(all(rva + len(code) <= UBISOFT.image_size for rva, code in probes.items()))
        self.assertEqual(UBISOFT.rva(session_request.REQUEST_STUB_RVA), UBISOFT.text1.rva + 0xA0)

    def test_unknown_reference_address_is_refused(self):
        with self.assertRaisesRegex(ValueError, "no known address"):
            UBISOFT.rva(0x1234)

    def test_storm_block_differs_only_in_the_two_call_displacements(self):
        steam, ubisoft = storm_peers.ORIGINAL_BLOCKS["steam"], storm_peers.ORIGINAL_BLOCKS["ubisoft"]

        self.assertEqual([i for i, (a, b) in enumerate(zip(steam, ubisoft)) if a != b], [0x23, 0x61])
        self.assertEqual(storm_peers.patched_block(build=UBISOFT)[0x23], 0xB4)


def containing(code, offset):
    """(instruction index, byte inside it) of a function offset."""
    index = bisect.bisect_right([start for start, _ in code], offset) - 1
    return index, offset - code[index][0]


class Image:
    def __init__(self, path, build: Build):
        self.build = build
        self.stream = path.open("rb")
        # Every section, the build lists only the ones that patches touch
        self.stream.seek(0x3C)
        header = struct.unpack("<I", self.stream.read(4))[0]
        self.stream.seek(header + 6)
        count = struct.unpack("<H", self.stream.read(2))[0]
        self.stream.seek(header + 20)
        optional_size = struct.unpack("<H", self.stream.read(2))[0]
        self.stream.seek(header + 24 + optional_size)
        self.sections = [struct.unpack_from("<IIII", self.stream.read(40), 8) for _ in range(count)]
        table = self.read(build.exception_table_rva, build.exception_table_size)
        self.functions = list(struct.iter_unpack("<III", table))
        self.starts = [entry[0] for entry in self.functions]

    def close(self):
        self.stream.close()

    def read(self, rva, size):
        _, start, raw_size, offset = next(section for section in self.sections
                                          if section[1] <= rva and rva + size <= section[1] + section[2])
        self.stream.seek(offset + rva - start)
        return self.stream.read(size)

    def function(self, rva):
        start, end, _ = self.functions[bisect.bisect_right(self.starts, rva) - 1]
        if not start <= rva < end:
            raise AssertionError(f"RVA {rva:#x} is outside every runtime function")
        return start, end

    def instructions(self, start, end):
        """(offset, text) with RIP displacements masked and branches named by target instruction."""
        code = [(instruction.address - start, instruction.mnemonic,
                 re.sub(r"rip [+-] 0x[0-9a-f]+", "rip", instruction.op_str))
                for instruction in DISASSEMBLER.disasm(self.read(start, end - start), start)]
        # The Steam compile carries one junk store that the Ubisoft compile lacks
        code = [item for item in code if not (item[1] == "and" and item[2].startswith("qword ptr [rip]"))]
        offsets = [offset for offset, _, _ in code]
        result = []
        for offset, mnemonic, operands in code:
            if re.fullmatch(r"0x[0-9a-f]+", operands):
                target = int(operands, 16) - start
                operands = f"#{offsets.index(target)}" if target in offsets else "far"
            result.append((offset, f"{mnemonic} {operands}"))
        return result


@unittest.skipUnless(ORIGINAL_DLL and UBISOFT_DLL, "Needs pristine Steam and Ubisoft FC6 DLLs")
class TestUbisoftRelocations(unittest.TestCase):
    """Every relocated address sits in a function with the same instructions as the Steam one."""

    @classmethod
    def setUpClass(cls):
        cls.steam = Image(ORIGINAL_DLL, STEAM)
        cls.ubisoft = Image(UBISOFT_DLL, UBISOFT)

    @classmethod
    def tearDownClass(cls):
        cls.steam.close()
        cls.ubisoft.close()

    def test_code_relocations_land_on_the_same_instruction_of_the_same_function(self):
        for steam_rva, ubisoft_rva in UBISOFT.relocations.items():
            if steam_rva in DATA_RVAS:
                continue
            with self.subTest(hex(steam_rva)):
                if steam_rva in LEAF_WINDOWS:
                    size = LEAF_WINDOWS[steam_rva]
                    steam_range, ubisoft_range = (steam_rva, steam_rva + size), (ubisoft_rva, ubisoft_rva + size)
                else:
                    steam_range, ubisoft_range = self.steam.function(steam_rva), self.ubisoft.function(ubisoft_rva)
                steam_code = self.steam.instructions(*steam_range)
                ubisoft_code = self.ubisoft.instructions(*ubisoft_range)

                self.assertEqual([text for _, text in steam_code], [text for _, text in ubisoft_code])
                # Same instruction and the same byte inside it, the owner site skips a REX prefix
                self.assertEqual(containing(steam_code, steam_rva - steam_range[0]),
                                 containing(ubisoft_code, ubisoft_rva - ubisoft_range[0]))

    def test_data_relocations(self):
        for steam_rva, text in DATA_STRINGS.items():
            with self.subTest(text):
                self.assertEqual(self.steam.read(steam_rva, len(text)), text)
                self.assertEqual(self.ubisoft.read(UBISOFT.rva(steam_rva), len(text)), text)
        for build, image in ((STEAM, self.steam), (UBISOFT, self.ubisoft)):
            with self.subTest(build.name):
                probes = session_request.patched_code_probes(True, build)
                reference = build.rva(session_request.JSON_STRING_SETTER_NULL_REFERENCE_RVA)
                self.assertEqual(image.read(reference, 7), probes[reference])  # lea rax, [JSON null]


@unittest.skipUnless(UBISOFT_DLL, "Set FC6_UBISOFT_DLL to a pristine Ubisoft FC6 DLL")
class TestUbisoftBuild(unittest.TestCase):
    def test_source_is_the_supported_build(self):
        self.assertEqual(file_sha256(UBISOFT_DLL), UBISOFT.sha256)

    def test_recommended_variant_reproduces_its_pinned_hash(self):
        variant = get_variant(RECOMMENDED)
        edits = variant.edits(UBISOFT_DLL, UBISOFT)

        self.assertEqual(patched_sha256(UBISOFT_DLL, edits), variant.hash_for(UBISOFT))

    def test_original_probes_hold_in_the_pristine_file(self):
        image = Image(UBISOFT_DLL, UBISOFT)
        try:
            probes = session_request.patched_code_probes(True, UBISOFT)
            for reference in (session_request.JSON_GET_MEMBER_RVA, session_request.JSON_UTF8_SET_RVA):
                rva = UBISOFT.rva(reference)
                with self.subTest(hex(reference)):
                    self.assertEqual(image.read(rva, len(probes[rva])), probes[rva])
            hook = UBISOFT.rva(session_request.REQUEST_HOOK_RVA)
            self.assertEqual(image.read(hook, 7), session_request.REQUEST_HOOK_ORIGINAL)
            self.assertEqual(image.read(UBISOFT.text1.rva + 0x20, 0x140), bytes(0x140))
        finally:
            image.close()

    def test_runtime_function_is_inserted_in_order(self):
        image = Image(UBISOFT_DLL, UBISOFT)
        try:
            table = image.read(UBISOFT.exception_table_rva, UBISOFT.exception_table_size)
        finally:
            image.close()
        updated = session_request.add_runtime_function(table, True, UBISOFT)
        insertion = UBISOFT.exception_insert_index * 12
        starts = [entry[0] for entry in struct.iter_unpack("<III", updated)]

        self.assertEqual(updated[insertion:insertion + 12], session_request.runtime_function_entry(True, UBISOFT))
        self.assertEqual(starts, sorted(starts))


if __name__ == "__main__":
    unittest.main()
