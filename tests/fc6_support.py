"""Shared fixtures for the FC6 tests."""

import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fc6.build import STEAM, UBISOFT, Build  # noqa: E402

NATIVE_X64 = sys.platform == "win32" and struct.calcsize("P") == 8
SANDBOX_ROOT = ROOT / "local" / "far-cry-6" / "test-sandboxes"


def find_original_dll(build: Build = STEAM, variable: str = "FC6_ORIGINAL_DLL") -> Path | None:
    """The environment variable, else any pristine backup kept in an ignored local package."""
    configured = os.environ.get(variable)
    candidates = [Path(configured)] if configured else sorted(
        (ROOT / "local" / "far-cry-6").glob("*/FC_m64d3d12.dll.bak")
    )
    # Size is a cheap filter, tests that rely on content still check hashes or bytes
    return next((path for path in candidates if path.is_file() and path.stat().st_size == build.file_size), None)


ORIGINAL_DLL = find_original_dll()
UBISOFT_DLL = find_original_dll(UBISOFT, "FC6_UBISOFT_DLL")


class MemoryImage:
    def __init__(self):
        self.regions = {}
        self.reads = []

    def read(self, address, size):
        self.reads.append((address, size))
        for start, data in self.regions.items():
            offset = address - start
            if 0 <= offset and offset + size <= len(data):
                return bytes(data[offset:offset + size])
        return b""
