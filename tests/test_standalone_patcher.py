#!/usr/bin/env python3
"""
Regression Test Suite for Far Cry 5 Standalone Patcher CLI & Engine
"""

import sys
import shutil
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

import patch_engine as pe

PRISTINE_BACKUP_PATH = Path(r"S:\Games\Far Cry 5\bin\FC_m64.dll.bak")

class TestStandalonePatcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PRISTINE_BACKUP_PATH.exists():
            raise unittest.SkipTest("Pristine backup file not found")

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fc5_reg_")
        self.dll_path = Path(self.test_dir) / "FC_m64.dll"
        shutil.copyfile(PRISTINE_BACKUP_PATH, self.dll_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cli_status(self):
        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["status"], "ORIGINAL_PRISTINE")

    def test_tri_gate_3p_default(self):
        # Default behavior: camera fix enabled automatically
        ok = pe.apply_patch(self.dll_path, players=3)
        self.assertTrue(ok)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.KNOWN_TRI_CAM_HASHES[3])

    def test_tri_gate_3p_without_camera(self):
        # Explicit disable
        ok = pe.apply_patch(self.dll_path, players=3, camera_fix=False)
        self.assertTrue(ok)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.KNOWN_TRI_HASHES[3])

    def test_tri_gate_4p_default(self):
        ok = pe.apply_patch(self.dll_path, players=4)
        self.assertTrue(ok)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.KNOWN_TRI_CAM_HASHES[4])

    def test_restore(self):
        pe.apply_patch(self.dll_path, players=3)
        ok = pe.restore_original(self.dll_path)
        self.assertTrue(ok)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.ORIGINAL_SHA256)

if __name__ == "__main__":
    unittest.main()
