#!/usr/bin/env python3
"""
Automated Test Suite for Far Cry 5 Standalone Patcher with Cutscene Camera Fix
Tests independent capacity and camera patch combinations, safe backup,
idempotency, reversibility, and in-place restoration.
"""

import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path

# Add src to python path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

import patch_engine as pe

PRISTINE_BACKUP_PATH = Path(r"S:\Games\Far Cry 5\bin\FC_m64.dll.bak")

class TestCameraPatchIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PRISTINE_BACKUP_PATH.exists():
            raise unittest.SkipTest(f"Pristine backup file not found at {PRISTINE_BACKUP_PATH}")
        # Verify pristine backup hash
        cls.pristine_hash = pe.get_file_sha256(PRISTINE_BACKUP_PATH)
        if cls.pristine_hash != pe.ORIGINAL_SHA256:
            raise unittest.SkipTest("Pristine backup hash mismatch, skipping sandbox tests.")

    def setUp(self):
        # Create an isolated temporary sandbox directory for each test
        self.test_dir = tempfile.mkdtemp(prefix="fc5_test_")
        self.dll_path = Path(self.test_dir) / "FC_m64.dll"
        shutil.copyfile(PRISTINE_BACKUP_PATH, self.dll_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_constants_and_offsets(self):
        """Verify that RVA, file offset, and instruction bytes are exactly as verified in RE."""
        self.assertEqual(pe.CAMERA_FIX_RVA, 0x031CA87D)
        self.assertEqual(pe.CAMERA_FIX_OFFSET, 0x031C9E7D)
        self.assertEqual(pe.ORIGINAL_CAMERA_BYTES, bytes.fromhex("7560"))
        self.assertEqual(pe.PATCHED_CAMERA_BYTES, bytes.fromhex("7c60"))

        with open(self.dll_path, "rb") as f:
            f.seek(pe.CAMERA_FIX_OFFSET)
            current_bytes = f.read(2)
        self.assertEqual(current_bytes, pe.ORIGINAL_CAMERA_BYTES)

    def test_02_pristine_inspection(self):
        """Verify inspection of pristine binary."""
        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["status"], "ORIGINAL_PRISTINE")
        self.assertEqual(info["capacity"], 2)
        self.assertFalse(info["camera_fix_applied"])
        self.assertEqual(info["sha256"], pe.ORIGINAL_SHA256)

    def test_03_apply_camera_fix_only(self):
        """Verify applying only the camera fix to pristine DLL (Guest configuration)."""
        ok = pe.apply_patch(self.dll_path, players=2, camera_fix=True)
        self.assertTrue(ok)

        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["status"], "ORIGINAL_CAM_FIX")
        self.assertEqual(info["capacity"], 2)
        self.assertTrue(info["camera_fix_applied"])
        self.assertEqual(info["sha256"], pe.PATCHED_CAM_ONLY_SHA256)

        # Check backup was created and valid
        backup_path = self.dll_path.with_name("FC_m64.dll.bak")
        self.assertTrue(backup_path.exists())
        self.assertEqual(pe.get_file_sha256(backup_path), pe.ORIGINAL_SHA256)

    def test_04_apply_tri_gate_3p_with_camera(self):
        """Verify applying Tri-Gate 3P combined with camera fix."""
        ok = pe.apply_patch(self.dll_path, players=3, camera_fix=True)
        self.assertTrue(ok)

        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["status"], "PATCHED_TRI_GATE_CAM")
        self.assertEqual(info["capacity"], 3)
        self.assertTrue(info["camera_fix_applied"])
        self.assertEqual(info["sha256"], pe.KNOWN_TRI_CAM_HASHES[3])

    def test_05_apply_tri_gate_4p_with_camera(self):
        """Verify applying Tri-Gate 4P combined with camera fix."""
        ok = pe.apply_patch(self.dll_path, players=4, camera_fix=True)
        self.assertTrue(ok)

        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["status"], "PATCHED_TRI_GATE_CAM")
        self.assertEqual(info["capacity"], 4)
        self.assertTrue(info["camera_fix_applied"])
        self.assertEqual(info["sha256"], pe.KNOWN_TRI_CAM_HASHES[4])

    def test_06_toggle_camera_fix_preserves_capacity(self):
        """Verify that enabling/disabling camera fix preserves the capacity setting."""
        # 1. Apply 3P without camera fix
        ok = pe.apply_patch(self.dll_path, players=3, camera_fix=False)
        self.assertTrue(ok)
        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["sha256"], pe.KNOWN_TRI_HASHES[3])
        self.assertFalse(info["camera_fix_applied"])

        # 2. Enable camera fix while omitting players argument (preserve capacity)
        ok = pe.apply_patch(self.dll_path, camera_fix=True)
        self.assertTrue(ok)
        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["capacity"], 3)
        self.assertTrue(info["camera_fix_applied"])
        self.assertEqual(info["sha256"], pe.KNOWN_TRI_CAM_HASHES[3])

        # 3. Disable camera fix while omitting players argument
        ok = pe.apply_patch(self.dll_path, camera_fix=False)
        self.assertTrue(ok)
        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["capacity"], 3)
        self.assertFalse(info["camera_fix_applied"])
        self.assertEqual(info["sha256"], pe.KNOWN_TRI_HASHES[3])

    def test_07_toggle_capacity_preserves_camera_fix(self):
        """Verify that changing capacity preserves an active camera fix."""
        # 1. Start with 3P + camera fix
        pe.apply_patch(self.dll_path, players=3, camera_fix=True)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.KNOWN_TRI_CAM_HASHES[3])

        # 2. Switch to 4P while omitting camera_fix argument
        ok = pe.apply_patch(self.dll_path, players=4)
        self.assertTrue(ok)
        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["capacity"], 4)
        self.assertTrue(info["camera_fix_applied"])
        self.assertEqual(info["sha256"], pe.KNOWN_TRI_CAM_HASHES[4])

    def test_08_restore_from_camera_only(self):
        """Verify restoring to original pristine from camera-only patched build."""
        pe.apply_patch(self.dll_path, players=2, camera_fix=True)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.PATCHED_CAM_ONLY_SHA256)

        ok = pe.restore_original(self.dll_path)
        self.assertTrue(ok)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.ORIGINAL_SHA256)

        info = pe.inspect_binary(self.dll_path)
        self.assertEqual(info["status"], "ORIGINAL_PRISTINE")
        self.assertFalse(info["camera_fix_applied"])

    def test_09_restore_from_tri_gate_cam(self):
        """Verify restoring to original pristine from Tri-Gate + Camera build."""
        pe.apply_patch(self.dll_path, players=4, camera_fix=True)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.KNOWN_TRI_CAM_HASHES[4])

        ok = pe.restore_original(self.dll_path)
        self.assertTrue(ok)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.ORIGINAL_SHA256)

    def test_10_idempotency(self):
        """Verify that reapplying the same configuration performs a safe no-op."""
        pe.apply_patch(self.dll_path, players=3, camera_fix=True)
        hash_before = pe.get_file_sha256(self.dll_path)

        ok = pe.apply_patch(self.dll_path, players=3, camera_fix=True)
        self.assertTrue(ok)
        self.assertEqual(pe.get_file_sha256(self.dll_path), hash_before)

    def test_11_in_place_restore_fallback(self):
        """Verify in-place restoration works even if .bak backup is missing."""
        pe.apply_patch(self.dll_path, players=3, camera_fix=True)
        backup_path = self.dll_path.with_name("FC_m64.dll.bak")
        if backup_path.exists():
            backup_path.unlink()

        ok = pe.restore_original(self.dll_path)
        self.assertTrue(ok)
        self.assertEqual(pe.get_file_sha256(self.dll_path), pe.ORIGINAL_SHA256)

    def test_12_unsupported_binary_rejection(self):
        """Verify that unrecognized or modified binaries are safely rejected without force."""
        with open(self.dll_path, "r+b") as f:
            f.seek(0x500)
            f.write(b"\xde\xad\xbe\xef")

        ok = pe.apply_patch(self.dll_path, players=3, camera_fix=True, force=False)
        self.assertFalse(ok)

if __name__ == "__main__":
    unittest.main()
