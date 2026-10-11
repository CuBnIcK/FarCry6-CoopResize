#!/usr/bin/env python3
"""
Far Cry 5 3-Player Co-op — Hardened Runtime Session & Capacity Observer
Non-intrusive diagnostic tool monitoring Far Cry 5 process memory with explicit 64-bit Windows API types.

Features & Resilience:
  1. Module Identity Verification with Dual-Layer Checking:
     - On-disk file SHA-256 verification against known builds (Pristine, 3P/4P Net, Dual, Tri-Gate v1/v2).
     - In-memory PE NT header verification (TimeDateStamp, SizeOfImage, EntryPoint).
  2. Identity Caching & Ephemeral Header Handling:
     - Caches verified module identity for (PID, base, size).
     - Tracks header page transitions with GetLastError() codes.
  3. Verified CFCXPlayerService Object & Active Player Entity Traversal:
     - RVA 0x4fd27e0 is the global pointer variable (CFCXPlayerService* g_pPlayerService).
     - Verifies heap object address and Vtables (0x434a5b8 and 0x434a6b0).
     - Reads true player count at O+0x64 and capacity at O+0x60.
     - Traverses dynamic CPlayer* array at O+0x58, validating heap pointers and readiness byte (P+0xc8).
  4. Tri-Gate Instruction Telemetry:
     - Gate 1 (Network Session Target Capacity): mov eax, N at 0xa1a514a.
     - Gate 2 (Party Thunk Target Capacity): call 0x7ffaf40 thunk at 0xa7fba0.
     - Gate 3 (GameMode & Session Public Slots Capacity): GetGameModeDescriptor thunk at 0x948270.
  5. Live Session & Party Heap Structure Inspection:
     - Resolves and verifies runtime Session object (Vtable RVA 0x41fed48).
     - Reads true public slot capacity (Session + 0x2f2: MaxSlots).
     - Reads active participant slots (Session + 0x2f0: FilledSlots).
     - Reads connection reservations (Session + 0x2f1: ReservedSlots).
     - Calculates available slots (MaxSlots - ReservedSlots - FilledSlots).
     - Inspects associated GameModeDescriptor (ID, MinPlayers, MaxPlayers, MaxPartySize).
     - Resolves and verifies runtime Party object (Vtable RVA 0x43aaeb8, Party + 0x8e).
"""

import os
import sys
import json
import time
import struct
import ctypes
import hashlib
import argparse
import datetime as dt
from pathlib import Path
from ctypes import wintypes

# Explicit Windows API Function Signatures
k32 = ctypes.windll.kernel32

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
TH32CS_SNAPPROCESS        = 0x00000002
TH32CS_SNAPMODULE         = 0x00000008
TH32CS_SNAPMODULE32       = 0x00000010
INVALID_HANDLE_VALUE      = ctypes.c_void_p(-1).value
STILL_ACTIVE              = 259

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * wintypes.MAX_PATH),
    ]

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * wintypes.MAX_PATH),
    ]

class MBI64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("Alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("Alignment2", wintypes.DWORD),
    ]

k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE

k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CloseHandle.restype = wintypes.BOOL

k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32FirstW.restype = wintypes.BOOL

k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.restype = wintypes.BOOL

k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32FirstW.restype = wintypes.BOOL

k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32NextW.restype = wintypes.BOOL

k32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
k32.ReadProcessMemory.restype = wintypes.BOOL

k32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MBI64),
    ctypes.c_size_t,
]
k32.VirtualQueryEx.restype = ctypes.c_size_t

TARGET_EXE = "FarCry5.exe"
TARGET_DLL = "FC_m64.dll"

# Known SHA-256 signatures for bin\FC_m64.dll
ORIGINAL_SHA256          = "00833fae4d5d70213158a146ca98439b28a8e962b934885ecccd906204880af2"
PATCHED_NET_3P_SHA256    = "8c4209a456b6ca1614294346ffd56c02e13dfc49bbb2bffaab0a538e130e8a4c"
PATCHED_NET_4P_SHA256    = "af35f180bb657cb50fe8a2bbc88d34f289a81ab0aa84b07bd5fc68a57896b069"
PATCHED_DUAL_3P_SHA256   = "2d695933c9fb046b80c32de99d76d2e27c334f42b507cb104526b3583480f84f"
PATCHED_DUAL_4P_SHA256   = "68e39e009e4c347fd29bbd3375767ff8a517278bd91c66ac9cf00b0a2a02dc55"
PATCHED_TRI_V1_3P_SHA256 = "995c5815a394d89b0120fa18587503c4ff51375645f99a30faf87727b075f243"
PATCHED_TRI_V1_4P_SHA256 = "7a5fd4b77938dbe0a87f38c37c6b875aefd307fdbfbefe4b0c9d139eac72b34d"
PATCHED_TRI_3P_SHA256    = "3fa1b2a5b926be1d0b9919fdd356316840c75072beb68e889adb873ac6193ae1"
PATCHED_TRI_4P_SHA256    = "39e317cfa0dcbc7adcdf794fd57ce616066f046f6c00afe8a12b2b2c32c76743"

# Aliases for backwards compatibility
PATCHED_3P_SHA256 = PATCHED_TRI_3P_SHA256
PATCHED_4P_SHA256 = PATCHED_TRI_4P_SHA256

# Expected PE NT Header identity signatures for bin\FC_m64.dll
EXPECTED_TIMEDATESTAMP = 0x67ed5c34
EXPECTED_SIZEOFIMAGE   = 0xeea9000
EXPECTED_ENTRYPOINT    = 0xe3c3020

# Confirmed RVAs in bin\FC_m64.dll
RVA_CAPACITY_INSTR        = 0xa1a514a   # Gate 1: Network Session Capacity mov eax, N (5 bytes)
RVA_PARTY_THUNK           = 0xa7fba0    # Gate 2: GetMaxPartySizeForGameMode thunk (20 bytes)
RVA_SESSION_CAPACITY      = 0x948270    # Gate 3: GameMode & Session Public Slots Capacity thunk (33 bytes)
RVA_CGAMEMODE_PTR         = 0x4eb5a90   # Global CGameMode singleton pointer
RVA_PLAYER_SERVICE_PTR    = 0x4fd27e0   # Global CFCXPlayerService* pointer variable
RVA_VTABLE_PLAYER_SERVICE = 0x434a5b8   # Vtable of CFCXPlayerService (O+0x00)
RVA_VTABLE_PLAYER_SUB     = 0x434a6b0   # Vtable of CFCXPlayerService sub-object (O+0x50)
RVA_VTABLE_SESSION        = 0x41fed48   # Vtable of Session object
RVA_VTABLE_PARTY          = 0x43aaeb8   # Vtable of Party object

# Expected instruction bytes for Gate 2 thunk
PARTY_ORIGINAL_BYTES = bytes.fromhex("e99bb35707cccccccccccccccccccccccccccccc")
PARTY_3P_BYTES       = bytes.fromhex("4883ec28e897b357073c027502b0034883c428c3")
PARTY_4P_BYTES       = bytes.fromhex("4883ec28e897b357073c027502b0044883c428c3")

# Expected instruction bytes for Gate 3 thunk
SESSION_ORIGINAL_BYTES = bytes.fromhex("e95b160f07" + "cc" * 28)
SESSION_3P_BYTES       = bytes.fromhex("4883ec28e857160f074883c4284885c0740e807859027508c6405903c6405a03c3")
SESSION_4P_BYTES       = bytes.fromhex("4883ec28e857160f074883c4284885c0740e807859027508c6405904c6405a04c3")

def get_file_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def find_processes(name: str):
    h_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snap == INVALID_HANDLE_VALUE or not h_snap:
        return []
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    pids = []
    res = k32.Process32FirstW(h_snap, ctypes.byref(pe))
    while res:
        if pe.szExeFile.lower() == name.lower():
            pids.append(pe.th32ProcessID)
        res = k32.Process32NextW(h_snap, ctypes.byref(pe))
    k32.CloseHandle(h_snap)
    return pids

def find_module(pid: int, mod_name: str):
    h_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if h_snap == INVALID_HANDLE_VALUE or not h_snap:
        return None, None, None
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(MODULEENTRY32W)
    res = k32.Module32FirstW(h_snap, ctypes.byref(me))
    while res:
        if me.szModule.lower() == mod_name.lower():
            base = me.modBaseAddr
            size = me.modBaseSize
            path = me.szExePath
            k32.CloseHandle(h_snap)
            return base, size, path
        res = k32.Module32NextW(h_snap, ctypes.byref(me))
    k32.CloseHandle(h_snap)
    return None, None, None

def read_mem(h_proc, addr: int, size: int) -> bytes:
    if addr is None:
        return b""
    buf = ctypes.create_string_buffer(size)
    read_bytes = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(
        h_proc,
        ctypes.c_void_p(addr),
        buf,
        ctypes.c_size_t(size),
        ctypes.byref(read_bytes),
    )
    if not ok:
        return b""
    return buf.raw[:read_bytes.value]

def read_mem_ex(h_proc, addr: int, size: int) -> tuple[bytes, int]:
    if addr is None:
        return b"", 0
    buf = ctypes.create_string_buffer(size)
    read_bytes = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(
        h_proc,
        ctypes.c_void_p(addr),
        buf,
        ctypes.c_size_t(size),
        ctypes.byref(read_bytes),
    )
    if not ok:
        err = k32.GetLastError()
        return b"", err
    return buf.raw[:read_bytes.value], 0

def read_u64(h_proc, addr: int) -> int | None:
    data = read_mem(h_proc, addr, 8)
    if len(data) == 8:
        return struct.unpack("<Q", data)[0]
    return None

def read_u32(h_proc, addr: int) -> int | None:
    data = read_mem(h_proc, addr, 4)
    if len(data) == 4:
        return struct.unpack("<I", data)[0]
    return None

def read_u8(h_proc, addr: int) -> int | None:
    data = read_mem(h_proc, addr, 1)
    if len(data) == 1:
        return data[0]
    return None

class ModuleIdentityCache:
    def __init__(self):
        self.pid = None
        self.dll_base = None
        self.mod_size = None
        self.mod_path = ""
        self.disk_sha256 = ""
        self.disk_build_name = "UNKNOWN"
        self.is_verified = False
        self.validation_source = ""
        self.last_header_state = "UNKNOWN"

    def reset(self):
        self.__init__()

identity_cache = ModuleIdentityCache()

class RuntimeSessionTracker:
    def __init__(self):
        self.cached_session_addr = None
        self.cached_party_addr = None
        self.last_scan_time = 0.0

    def reset(self):
        self.cached_session_addr = None
        self.cached_party_addr = None
        self.last_scan_time = 0.0

    def read_session(self, h_proc, dll_base: int) -> dict | None:
        expected_vtable = dll_base + RVA_VTABLE_SESSION

        # 1. Fast verification of cached address
        if self.cached_session_addr:
            vt = read_u64(h_proc, self.cached_session_addr)
            if vt == expected_vtable:
                b = read_mem(h_proc, self.cached_session_addr + 0x2f0, 4)
                if len(b) == 4 and 1 <= b[2] <= 16:
                    filled, resv, max_slots = b[0], b[1], b[2]
                    avail = max(0, max_slots - resv - filled)
                    info = {
                        "address": hex(self.cached_session_addr),
                        "max_slots": max_slots,
                        "filled": filled,
                        "reserved": resv,
                        "available": avail,
                        "status": "VERIFIED_ACTIVE",
                    }
                    ptr_308 = read_u64(h_proc, self.cached_session_addr + 0x308)
                    if ptr_308:
                        gmd = read_u64(h_proc, ptr_308 + 8)
                        if gmd:
                            gmd_bytes = read_mem(h_proc, gmd + 0x48, 0x18)
                            if len(gmd_bytes) >= 0x13:
                                info["gmd_mode_id"] = hex(struct.unpack("<I", gmd_bytes[:4])[0])
                                info["gmd_min_players"] = gmd_bytes[0x10]
                                info["gmd_max_players"] = gmd_bytes[0x11]
                                info["gmd_max_party"] = gmd_bytes[0x12]
                    return info
            self.cached_session_addr = None

        # 2. Targeted heap scan for Session vtable
        pattern = struct.pack("<Q", expected_vtable)
        mbi = MBI64()
        addr = 0x10000000000
        max_addr = 0x35000000000

        while addr < max_addr:
            res = k32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(MBI64))
            if not res:
                break
            base = mbi.BaseAddress
            size = mbi.RegionSize
            if mbi.State == 0x1000 and (mbi.Protect & 0x04) and mbi.Type == 0x20000:
                chunk = 2 * 1024 * 1024
                off = 0
                while off < size:
                    to_read = min(chunk, size - off)
                    buf = ctypes.create_string_buffer(to_read)
                    nread = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(h_proc, ctypes.c_void_p(base + off), buf, to_read, ctypes.byref(nread)):
                        raw = buf.raw[:nread.value]
                        pos = 0
                        while True:
                            idx = raw.find(pattern, pos)
                            if idx == -1:
                                break
                            cand_addr = base + off + idx
                            b_cand = read_mem(h_proc, cand_addr + 0x2f0, 4)
                            if len(b_cand) == 4 and 1 <= b_cand[2] <= 16:
                                self.cached_session_addr = cand_addr
                                filled, resv, max_slots = b_cand[0], b_cand[1], b_cand[2]
                                avail = max(0, max_slots - resv - filled)
                                info = {
                                    "address": hex(cand_addr),
                                    "max_slots": max_slots,
                                    "filled": filled,
                                    "reserved": resv,
                                    "available": avail,
                                    "status": "VERIFIED_ACTIVE",
                                }
                                ptr_308 = read_u64(h_proc, cand_addr + 0x308)
                                if ptr_308:
                                    gmd = read_u64(h_proc, ptr_308 + 8)
                                    if gmd:
                                        gmd_bytes = read_mem(h_proc, gmd + 0x48, 0x18)
                                        if len(gmd_bytes) >= 0x13:
                                            info["gmd_mode_id"] = hex(struct.unpack("<I", gmd_bytes[:4])[0])
                                            info["gmd_min_players"] = gmd_bytes[0x10]
                                            info["gmd_max_players"] = gmd_bytes[0x11]
                                            info["gmd_max_party"] = gmd_bytes[0x12]
                                return info
                            pos = idx + 1
                    off += to_read
            addr = base + size

        return None

    def read_party(self, h_proc, dll_base: int) -> dict | None:
        expected_vtable = dll_base + RVA_VTABLE_PARTY

        # 1. Fast verification of cached address
        if self.cached_party_addr:
            vt = read_u64(h_proc, self.cached_party_addr)
            if vt == expected_vtable:
                b = read_mem(h_proc, self.cached_party_addr + 0x8e, 2)
                if len(b) == 2 and 1 <= b[0] <= 16:
                    return {
                        "address": hex(self.cached_party_addr),
                        "party_limit": b[0],
                        "is_set": b[1],
                        "status": "VERIFIED_ACTIVE",
                    }
            self.cached_party_addr = None

        # 2. Targeted heap scan for Party vtable
        pattern = struct.pack("<Q", expected_vtable)
        mbi = MBI64()
        addr = 0x10000000000
        max_addr = 0x35000000000

        while addr < max_addr:
            res = k32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(MBI64))
            if not res:
                break
            base = mbi.BaseAddress
            size = mbi.RegionSize
            if mbi.State == 0x1000 and (mbi.Protect & 0x04) and mbi.Type == 0x20000:
                chunk = 2 * 1024 * 1024
                off = 0
                while off < size:
                    to_read = min(chunk, size - off)
                    buf = ctypes.create_string_buffer(to_read)
                    nread = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(h_proc, ctypes.c_void_p(base + off), buf, to_read, ctypes.byref(nread)):
                        raw = buf.raw[:nread.value]
                        pos = 0
                        while True:
                            idx = raw.find(pattern, pos)
                            if idx == -1:
                                break
                            cand_addr = base + off + idx
                            b_cand = read_mem(h_proc, cand_addr + 0x8e, 2)
                            if len(b_cand) == 2 and 1 <= b_cand[0] <= 16:
                                self.cached_party_addr = cand_addr
                                return {
                                    "address": hex(cand_addr),
                                    "party_limit": b_cand[0],
                                    "is_set": b_cand[1],
                                    "status": "VERIFIED_ACTIVE",
                                }
                            pos = idx + 1
                    off += to_read
            addr = base + size

        return None

session_tracker = RuntimeSessionTracker()

def inspect_header_page(h_proc, dll_base: int) -> dict:
    info = {
        "status": "UNKNOWN",
        "details": "",
        "error_code": 0,
        "dos_magic": None,
        "timedatestamp": None,
        "entrypoint": None,
        "sizeofimage": None,
    }

    dos_data, err = read_mem_ex(h_proc, dll_base, 0x40)
    if len(dos_data) < 0x40:
        info["status"] = "UNREADABLE"
        info["error_code"] = err
        info["details"] = f"ReadProcessMemory failed with error code {err} (GetLastError: {err})"
        return info

    dos_magic = dos_data[:2]
    info["dos_magic"] = dos_magic.hex()
    if dos_magic != b"MZ":
        info["status"] = "MODIFIED_NON_MZ"
        info["details"] = f"Header page readable but DOS magic is not MZ ({dos_magic.hex()})"
        return info

    lfanew = struct.unpack("<I", dos_data[0x3c:0x40])[0]
    if lfanew > 0x1000:
        info["status"] = "CORRUPT_LFANEW"
        info["details"] = f"e_lfanew exceeds page boundary (0x{lfanew:x})"
        return info

    nt_base = dll_base + lfanew
    pe_sig, err_pe = read_mem_ex(h_proc, nt_base, 4)
    if pe_sig != b"PE\x00\x00":
        info["status"] = "INVALID_PE_SIGNATURE"
        info["details"] = f"Invalid PE signature: {pe_sig.hex()}"
        return info

    tds = read_u32(h_proc, nt_base + 8)
    ep  = read_u32(h_proc, nt_base + 0x28)
    soi = read_u32(h_proc, nt_base + 0x50)

    info["timedatestamp"] = tds
    info["entrypoint"] = ep
    info["sizeofimage"] = soi

    if tds == EXPECTED_TIMEDATESTAMP and ep == EXPECTED_ENTRYPOINT and soi == EXPECTED_SIZEOFIMAGE:
        info["status"] = "VALID"
        info["details"] = "Verified bin/FC_m64.dll reference NT headers"
    else:
        info["status"] = "BUILD_MISMATCH"
        info["details"] = (
            f"NT Header mismatch! TimeDateStamp: 0x{tds:08x}, EntryPoint: 0x{ep:08x}, Size: 0x{soi:08x}. "
            f"Expected: 0x{EXPECTED_TIMEDATESTAMP:08x}, 0x{EXPECTED_ENTRYPOINT:08x}, 0x{EXPECTED_SIZEOFIMAGE:08x}"
        )

    return info

def verify_and_cache_module_identity(h_proc, pid: int, dll_base: int, mod_size: int, mod_path: str) -> tuple[bool, str]:
    global identity_cache

    disk_path = Path(mod_path)
    disk_hash = get_file_sha256(disk_path) if disk_path.exists() else ""

    if disk_hash == ORIGINAL_SHA256:
        disk_build = "PRISTINE (2 Players)"
    elif disk_hash == PATCHED_TRI_3P_SHA256:
        disk_build = "PATCHED_TRI (3 Players)"
    elif disk_hash == PATCHED_TRI_4P_SHA256:
        disk_build = "PATCHED_TRI (4 Players)"
    elif disk_hash == PATCHED_TRI_V1_3P_SHA256:
        disk_build = "PATCHED_TRI_V1 (3 Players)"
    elif disk_hash == PATCHED_TRI_V1_4P_SHA256:
        disk_build = "PATCHED_TRI_V1 (4 Players)"
    elif disk_hash == PATCHED_DUAL_3P_SHA256:
        disk_build = "PATCHED_DUAL (3 Players)"
    elif disk_hash == PATCHED_DUAL_4P_SHA256:
        disk_build = "PATCHED_DUAL (4 Players)"
    elif disk_hash == PATCHED_NET_3P_SHA256:
        disk_build = "PATCHED_NET_ONLY (3 Players)"
    elif disk_hash == PATCHED_NET_4P_SHA256:
        disk_build = "PATCHED_NET_ONLY (4 Players)"
    else:
        disk_build = f"CUSTOM / UNRECOGNIZED ({disk_hash[:16]}...)" if disk_hash else "ON_DISK_UNAVAILABLE"

    if "bin_plus" in mod_path.lower() or mod_size != EXPECTED_SIZEOFIMAGE:
        reason = f"Module size (0x{mod_size:x}) or path ({mod_path}) does not match bin/FC_m64.dll (expected 0x{EXPECTED_SIZEOFIMAGE:x})"
        return False, reason

    hdr_info = inspect_header_page(h_proc, dll_base)

    is_verified = False
    validation_source = ""

    recognized_hashes = (
        ORIGINAL_SHA256,
        PATCHED_TRI_3P_SHA256,
        PATCHED_TRI_4P_SHA256,
        PATCHED_TRI_V1_3P_SHA256,
        PATCHED_TRI_V1_4P_SHA256,
        PATCHED_DUAL_3P_SHA256,
        PATCHED_DUAL_4P_SHA256,
        PATCHED_NET_3P_SHA256,
        PATCHED_NET_4P_SHA256,
    )

    if hdr_info["status"] == "VALID":
        is_verified = True
        validation_source = "IN_MEMORY_NT_HEADERS"
    elif disk_hash in recognized_hashes and mod_size == EXPECTED_SIZEOFIMAGE:
        is_verified = True
        validation_source = f"ON_DISK_HASH ({disk_build}) + IMAGE_SIZE"

    if is_verified:
        identity_cache.pid = pid
        identity_cache.dll_base = dll_base
        identity_cache.mod_size = mod_size
        identity_cache.mod_path = mod_path
        identity_cache.disk_sha256 = disk_hash
        identity_cache.disk_build_name = disk_build
        identity_cache.is_verified = True
        identity_cache.validation_source = validation_source
        identity_cache.last_header_state = hdr_info["status"]
        return True, f"Verified via {validation_source} [{disk_build}]"
    else:
        reason = f"Identity verification failed: In-memory: {hdr_info['details']} | On-disk: {disk_build}"
        return False, reason

def read_player_service_state(h_proc, dll_base: int, mod_size: int) -> dict:
    result = {
        "service_ptr": None,
        "service_verified": False,
        "service_status": "NOT_INSTANTIATED",
        "active_players_count": 0,
        "capacity": 0,
        "player_array_ptr": None,
        "pending_queue_head": None,
        "players": [],
    }

    service_ptr = read_u64(h_proc, dll_base + RVA_PLAYER_SERVICE_PTR)
    if not service_ptr:
        result["service_status"] = "NOT_INSTANTIATED (MAIN_MENU)"
        result["active_players_count"] = 0
        return result

    result["service_ptr"] = hex(service_ptr)

    if dll_base <= service_ptr < dll_base + mod_size or service_ptr < 0x10000:
        result["service_status"] = f"UNVERIFIED (INVALID_HEAP_POINTER: {hex(service_ptr)})"
        result["active_players_count"] = None
        return result

    vtable_o = read_u64(h_proc, service_ptr)
    vtable_s = read_u64(h_proc, service_ptr + 0x50)

    expected_vtable_o = dll_base + RVA_VTABLE_PLAYER_SERVICE
    expected_vtable_s = dll_base + RVA_VTABLE_PLAYER_SUB

    if vtable_o != expected_vtable_o or vtable_s != expected_vtable_s:
        result["service_status"] = f"UNVERIFIED (VTABLE_MISMATCH: got 0x{vtable_o:x}, expected 0x{expected_vtable_o:x})"
        result["active_players_count"] = None
        return result

    result["service_verified"] = True
    result["service_status"] = "VERIFIED_CFCXPlayerService"

    raw_count = read_u32(h_proc, service_ptr + 0x64)
    raw_capacity = read_u32(h_proc, service_ptr + 0x60)

    if raw_count is None or raw_capacity is None:
        result["service_status"] = "UNVERIFIED (COUNT_READ_FAILED)"
        result["active_players_count"] = None
        return result

    count = raw_count & 0x7fffffff
    capacity = raw_capacity
    result["capacity"] = capacity

    if count > 16 or (capacity > 0 and count > capacity):
        result["service_status"] = f"UNVERIFIED (ANOMALOUS_COUNT: count={count}, cap={capacity})"
        result["active_players_count"] = None
        return result

    result["active_players_count"] = count

    array_ptr = read_u64(h_proc, service_ptr + 0x58)
    result["player_array_ptr"] = hex(array_ptr) if array_ptr else None

    pending_head = read_u64(h_proc, service_ptr + 0xa0)
    result["pending_queue_head"] = hex(pending_head) if pending_head else None

    players = []
    if count > 0 and array_ptr:
        if not (dll_base <= array_ptr < dll_base + mod_size) and array_ptr >= 0x10000:
            for i in range(min(count, 8)):
                p_ptr = read_u64(h_proc, array_ptr + i * 8)
                if p_ptr and not (dll_base <= p_ptr < dll_base + mod_size) and p_ptr >= 0x10000:
                    ready_byte = read_u8(h_proc, p_ptr + 0xc8)
                    players.append({
                        "slot": i,
                        "pointer": hex(p_ptr),
                        "ready": ready_byte,
                    })
                elif p_ptr:
                    players.append({
                        "slot": i,
                        "pointer": hex(p_ptr),
                        "ready": None,
                        "warning": "INVALID_ENTITY_POINTER",
                    })

    result["players"] = players
    return result

def sample_engine_state(h_proc, pid: int, dll_base: int, mod_size: int, mod_path: str) -> dict:
    global identity_cache, session_tracker

    state = {
        "mod_path": mod_path,
        "dll_base": hex(dll_base) if dll_base else None,
        "mod_size": hex(mod_size) if mod_size else None,
    }

    # 1. Verify or retrieve cached module identity
    if not identity_cache.is_verified or identity_cache.pid != pid or identity_cache.dll_base != dll_base:
        success, reason = verify_and_cache_module_identity(h_proc, pid, dll_base, mod_size, mod_path)
        if not success:
            state["dll_build_verified"] = False
            state["error"] = "LOADED_DLL_BUILD_MISMATCH"
            state["error_details"] = reason
            state["net_target_capacity"] = None
            state["party_target_capacity"] = None
            state["gate3_target_capacity"] = None
            state["actual_session_capacity"] = None
            state["session_capacity_status"] = "UNVERIFIED (BUILD_MISMATCH)"
            state["campaign_session_created"] = False
            return state

    state["dll_build_verified"] = True
    state["disk_build"] = identity_cache.disk_build_name
    state["validation_source"] = identity_cache.validation_source

    # 2. Track in-memory header status & transitions
    hdr_info = inspect_header_page(h_proc, dll_base)
    state["header_status"] = hdr_info["status"]
    state["header_details"] = hdr_info["details"]

    if hdr_info["status"] != identity_cache.last_header_state:
        old_st = identity_cache.last_header_state
        new_st = hdr_info["status"]
        identity_cache.last_header_state = new_st
        state["header_transition"] = f"{old_st} -> {new_st}"

    # 3a. Gate 1: Network Session Capacity (mov eax, N at RVA 0xa1a514a)
    instr_bytes, instr_err = read_mem_ex(h_proc, dll_base + RVA_CAPACITY_INSTR, 5)
    if len(instr_bytes) == 5:
        state["net_instruction_hex"] = instr_bytes.hex()
        if instr_bytes == bytes.fromhex("b802000000"):
            state["net_target_capacity"] = 2
            state["net_instruction_disasm"] = "mov eax, 2 (PRISTINE)"
        elif instr_bytes == bytes.fromhex("b803000000"):
            state["net_target_capacity"] = 3
            state["net_instruction_disasm"] = "mov eax, 3 (PATCHED 3-PLAYER)"
        elif instr_bytes == bytes.fromhex("b804000000"):
            state["net_target_capacity"] = 4
            state["net_instruction_disasm"] = "mov eax, 4 (PATCHED 4-PLAYER)"
        else:
            state["net_target_capacity"] = None
            state["net_instruction_disasm"] = f"custom ({instr_bytes.hex()})"
    else:
        state["net_target_capacity"] = None
        state["net_instruction_disasm"] = f"UNREADABLE (error {instr_err})"

    state["instruction_hex"] = state.get("net_instruction_hex")
    state["patch_target_capacity"] = state.get("net_target_capacity")
    state["instruction_disasm"] = state.get("net_instruction_disasm")

    # 3b. Gate 2: Party System Capacity Thunk (RVA 0xa7fba0)
    party_bytes, party_err = read_mem_ex(h_proc, dll_base + RVA_PARTY_THUNK, 20)
    if len(party_bytes) == 20:
        state["party_instruction_hex"] = party_bytes.hex()
        if party_bytes == PARTY_ORIGINAL_BYTES:
            state["party_target_capacity"] = 2
            state["party_instruction_disasm"] = "jmp 0x7ffaf40 (PRISTINE, 2-PLAYER COOP)"
        elif party_bytes == PARTY_3P_BYTES:
            state["party_target_capacity"] = 3
            state["party_instruction_disasm"] = "call 0x7ffaf40; cmp 2; mov 3 (PATCHED 3-PLAYER)"
        elif party_bytes == PARTY_4P_BYTES:
            state["party_target_capacity"] = 4
            state["party_instruction_disasm"] = "call 0x7ffaf40; cmp 2; mov 4 (PATCHED 4-PLAYER)"
        else:
            state["party_target_capacity"] = None
            state["party_instruction_disasm"] = f"custom ({party_bytes[:8].hex()}...)"
    else:
        state["party_target_capacity"] = None
        state["party_instruction_disasm"] = f"UNREADABLE (error {party_err})"

    # 3c. Gate 3: GameMode & Session Public Slots Capacity (RVA 0x948270, 33 bytes)
    sess_bytes, sess_err = read_mem_ex(h_proc, dll_base + RVA_SESSION_CAPACITY, 33)
    if len(sess_bytes) == 33:
        state["gate3_instruction_hex"] = sess_bytes.hex()
        if sess_bytes == SESSION_ORIGINAL_BYTES:
            state["gate3_target_capacity"] = 2
            state["gate3_instruction_disasm"] = "jmp 0x7a398d0 (PRISTINE, 2-PLAYER)"
        elif sess_bytes == SESSION_3P_BYTES:
            state["gate3_target_capacity"] = 3
            state["gate3_instruction_disasm"] = "call 0x7a398d0; promote 3P (PATCHED 3-PLAYER)"
        elif sess_bytes == SESSION_4P_BYTES:
            state["gate3_target_capacity"] = 4
            state["gate3_instruction_disasm"] = "call 0x7a398d0; promote 4P (PATCHED 4-PLAYER)"
        else:
            state["gate3_target_capacity"] = None
            state["gate3_instruction_disasm"] = f"CUSTOM ({sess_bytes[:8].hex()}...)"
    else:
        state["gate3_target_capacity"] = None
        state["gate3_instruction_disasm"] = f"UNREADABLE ({sess_err})"

    # 4. CGameMode feature flag (+0x78)
    cgamemode_ptr = read_u64(h_proc, dll_base + RVA_CGAMEMODE_PTR)
    state["cgamemode_ptr"] = hex(cgamemode_ptr) if cgamemode_ptr else None
    if cgamemode_ptr:
        state["feature_flag_78"] = read_u8(h_proc, cgamemode_ptr + 0x78)
    else:
        state["feature_flag_78"] = None

    # 5. Verified CFCXPlayerService Traversal
    ps_state = read_player_service_state(h_proc, dll_base, mod_size)
    state["player_service_ptr"] = ps_state["service_ptr"]
    state["player_service_status"] = ps_state["service_status"]
    state["active_players_count"] = ps_state["active_players_count"]
    state["player_array_ptr"] = ps_state["player_array_ptr"]
    state["pending_queue_head"] = ps_state["pending_queue_head"]
    state["players"] = ps_state["players"]

    # 6. Read Live Session Object (+0x2f0, +0x2f1, +0x2f2)
    sess_info = session_tracker.read_session(h_proc, dll_base)
    if sess_info:
        state["actual_session_capacity"] = sess_info["max_slots"]
        state["session_filled_slots"] = sess_info["filled"]
        state["session_reserved_slots"] = sess_info["reserved"]
        state["session_available_slots"] = sess_info["available"]
        state["session_address"] = sess_info["address"]
        state["session_gmd_info"] = {
            "mode_id": sess_info.get("gmd_mode_id"),
            "min_players": sess_info.get("gmd_min_players"),
            "max_players": sess_info.get("gmd_max_players"),
            "max_party": sess_info.get("gmd_max_party"),
        }
        state["session_capacity_status"] = f"VERIFIED_SESSION (Filled: {sess_info['filled']}/{sess_info['max_slots']}, Avail: {sess_info['available']})"
        state["campaign_session_created"] = True
    else:
        active_count = ps_state["active_players_count"]
        state["actual_session_capacity"] = None
        state["session_filled_slots"] = None
        state["session_reserved_slots"] = None
        state["session_available_slots"] = None
        state["session_address"] = None

        if active_count is None:
            state["campaign_session_created"] = False
            state["session_capacity_status"] = f"UNVERIFIED ({ps_state['service_status']})"
        elif active_count == 0:
            state["campaign_session_created"] = False
            state["session_capacity_status"] = "LOBBY_INACTIVE (MAIN_MENU)"
        elif active_count == 1:
            state["campaign_session_created"] = False
            state["session_capacity_status"] = "SINGLE_PLAYER_ACTIVE (NO_COOP_SESSION)"
        else:
            state["campaign_session_created"] = True
            state["session_capacity_status"] = "UNVERIFIED (DESCRIPTOR_UNRESOLVED)"

    # 7. Read Live Party Object (Party + 0x8e)
    party_info = session_tracker.read_party(h_proc, dll_base)
    if party_info:
        state["actual_party_limit"] = party_info["party_limit"]
        state["party_is_set"] = party_info["is_set"]
        state["party_address"] = party_info["address"]
    else:
        state["actual_party_limit"] = None
        state["party_is_set"] = None
        state["party_address"] = None

    return state

def is_process_alive(h_proc) -> bool:
    if not h_proc or h_proc == INVALID_HANDLE_VALUE:
        return False
    exit_code = wintypes.DWORD(0)
    if k32.GetExitCodeProcess(h_proc, ctypes.byref(exit_code)):
        return exit_code.value == STILL_ACTIVE
    return False

def main():
    parser = argparse.ArgumentParser(
        description="Far Cry 5 Hardened Runtime Session Observer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/observe_session_runtime.py
  python src/observe_session_runtime.py --interval 0.5 --log reports/session_events.jsonl
        """
    )
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds (default: 1.0)")
    parser.add_argument("--log", type=Path, default=Path("reports/runtime_session_events.jsonl"), help="JSONL log path")
    args = parser.parse_args()

    args.log.parent.mkdir(parents=True, exist_ok=True)
    print("=" * 80)
    print("Far Cry 5 3-Player Co-op — Hardened Tri-Gate Runtime Session Observer")
    print("=" * 80)
    print(f"Target process: {TARGET_EXE}")
    print(f"Target module:  {TARGET_DLL}")
    print(f"Log path:       {args.log}")
    print("Waiting for game process to start...\n")

    attached_pid = None
    h_proc = None
    dll_base = None
    mod_size = None
    mod_path = ""
    last_log_state = None

    try:
        with open(args.log, "a", encoding="utf-8") as log_file:
            while True:
                if attached_pid:
                    if not is_process_alive(h_proc):
                        print(f"[*] Process {TARGET_EXE} (PID {attached_pid}) exited. Resetting observer state...\n")
                        k32.CloseHandle(h_proc)
                        attached_pid = None
                        h_proc = None
                        dll_base = None
                        mod_size = None
                        mod_path = ""
                        identity_cache.reset()
                        session_tracker.reset()
                        time.sleep(args.interval)
                        continue

                if not attached_pid:
                    pids = find_processes(TARGET_EXE)
                    if pids:
                        attached_pid = pids[0]
                        h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, attached_pid)
                        if not h_proc or h_proc == INVALID_HANDLE_VALUE:
                            print(f"[!] Found {TARGET_EXE} (PID {attached_pid}) but failed to open handle. Retrying...")
                            attached_pid = None
                            time.sleep(args.interval)
                            continue
                        print(f"[+] Attached to {TARGET_EXE} (PID: {attached_pid})")
                    else:
                        time.sleep(args.interval)
                        continue

                if not dll_base:
                    base, size, path = find_module(attached_pid, TARGET_DLL)
                    if base:
                        dll_base = base
                        mod_size = size
                        mod_path = path
                        print(f"[+] Located {TARGET_DLL} at base 0x{dll_base:x} (Size: 0x{mod_size:x}, Path: {mod_path})")
                    else:
                        time.sleep(args.interval)
                        continue

                state = sample_engine_state(h_proc, attached_pid, dll_base, mod_size, mod_path)
                timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
                state["timestamp"] = timestamp
                state["pid"] = attached_pid

                log_file.write(json.dumps(state) + "\n")
                log_file.flush()

                if "header_transition" in state:
                    print(f"[*] [{timestamp}] PE header state transition: {state['header_transition']} ({state.get('header_details', '')})")

                if "error" in state:
                    err_msg = f"{state['error']}: {state.get('error_details', '')}"
                    if err_msg != last_log_state:
                        print(f"[{timestamp}] [ERROR] {err_msg}")
                        last_log_state = err_msg
                else:
                    p0_str = "None"
                    if state.get("players"):
                        p0 = state["players"][0]
                        p0_str = f"Slot0:{p0['pointer']}(Ready:{p0.get('ready')})"

                    if state.get("actual_session_capacity") is not None:
                        sess_cap_str = f"{state['actual_session_capacity']} (Filled: {state.get('session_filled_slots')}/{state['actual_session_capacity']}, Avail: {state.get('session_available_slots')})"
                    else:
                        sess_cap_str = f"None ({state.get('session_capacity_status', 'UNVERIFIED')})"

                    party_lim_str = str(state.get("actual_party_limit")) if state.get("actual_party_limit") is not None else "None"

                    line_summary = (
                        f"[{timestamp}] "
                        f"NetCap: {state.get('net_target_capacity')} | "
                        f"PartyCap: {state.get('party_target_capacity')} | "
                        f"Gate3Cap: {state.get('gate3_target_capacity')} | "
                        f"PartyLimit: {party_lim_str} | "
                        f"SessionCap: {sess_cap_str} | "
                        f"Players: {state.get('active_players_count')} | "
                        f"P0: {p0_str}"
                    )
                    print(line_summary)
                    last_log_state = None

                time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[*] Observer stopped by user.")
    finally:
        if h_proc and h_proc != INVALID_HANDLE_VALUE:
            k32.CloseHandle(h_proc)
        identity_cache.reset()
        session_tracker.reset()
        print("[*] Cleanup complete.")

if __name__ == "__main__":
    main()
