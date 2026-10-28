import shutil
import tempfile
import unittest
from pathlib import Path

from fc6_support import ORIGINAL_DLL, SANDBOX_ROOT, UBISOFT_DLL

from fc6.build import STEAM, TARGET_DLL, UBISOFT
from fc6.edits import file_sha256
from fc6.install import backup_path, find_dll, inspect, install, restore
from fc6.variants import ORIGINAL, RECOMMENDED, get_variant


class Sandbox(unittest.TestCase):
    def setUp(self):
        SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
        self.sandbox = tempfile.TemporaryDirectory(dir=SANDBOX_ROOT)
        self.game = Path(self.sandbox.name) / "Far Cry 6"
        (self.game / "bin").mkdir(parents=True)
        self.dll = self.game / "bin" / TARGET_DLL

    def tearDown(self):
        self.sandbox.cleanup()


class TestFindDll(Sandbox):
    def test_accepts_game_folder_bin_folder_and_dll(self):
        self.dll.write_bytes(b"dll")

        for location in (self.game, self.game / "bin", self.dll):
            self.assertEqual(find_dll(location), self.dll.resolve())

    def test_missing_dll_is_reported(self):
        with self.assertRaises(FileNotFoundError):
            find_dll(self.game)

    def test_unknown_dll_is_refused_and_left_alone(self):
        self.dll.write_bytes(b"not the game")

        self.assertIsNone(inspect(self.dll).build)
        with self.assertRaisesRegex(ValueError, "Unsupported game version"):
            install(self.dll)
        self.assertEqual(self.dll.read_bytes(), b"not the game")
        self.assertFalse(backup_path(self.dll).exists())


class TestInstallRestore(Sandbox):
    def round_trip(self, source: Path, build):
        shutil.copyfile(source, self.dll)
        expected = get_variant(RECOMMENDED).hash_for(build)

        self.assertIn("Installed", install(self.dll))
        self.assertEqual(file_sha256(self.dll), expected)
        self.assertEqual(file_sha256(backup_path(self.dll)), build.sha256)
        self.assertIn("already installed", install(self.dll))

        self.assertIn("Restored", restore(self.dll))
        self.assertEqual(file_sha256(self.dll), build.sha256)
        self.assertIs(inspect(self.dll).variant, ORIGINAL)
        self.assertIn("already the original", restore(self.dll))
        self.assertEqual(sorted(path.name for path in self.dll.parent.iterdir()),
                         [TARGET_DLL, TARGET_DLL + ".bak"])

        # A patched DLL without its backup cannot be restored or re-patched
        install(self.dll)
        backup_path(self.dll).unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            restore(self.dll)
        self.assertEqual(file_sha256(self.dll), expected)

    @unittest.skipUnless(ORIGINAL_DLL, "Set FC6_ORIGINAL_DLL to the Steam DLL")
    def test_steam_round_trip(self):
        self.round_trip(ORIGINAL_DLL, STEAM)

    @unittest.skipUnless(UBISOFT_DLL, "Set FC6_UBISOFT_DLL to the Ubisoft Connect DLL")
    def test_ubisoft_round_trip(self):
        self.round_trip(UBISOFT_DLL, UBISOFT)

    @unittest.skipUnless(ORIGINAL_DLL, "Set FC6_ORIGINAL_DLL to the Steam DLL")
    def test_damaged_backup_is_replaced_from_the_original_dll(self):
        shutil.copyfile(ORIGINAL_DLL, self.dll)
        backup_path(self.dll).write_bytes(b"stale")

        install(self.dll)

        self.assertEqual(file_sha256(backup_path(self.dll)), STEAM.sha256)


if __name__ == "__main__":
    unittest.main()
