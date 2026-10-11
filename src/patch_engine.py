#!/usr/bin/env python3
"""
Far Cry 5 Co-op Patcher Core Engine
Authoritative Parameterized Tri-Gate Patching System with Process Safety,
Installation Auto-Detection, PE Validation, and Reversible Restoration.
"""

import os
import sys
import uuid
import shutil
import struct
import hashlib
from pathlib import Path
from typing import Callable, Optional, Dict, Any, List, Tuple

try:
    import winreg
except ImportError:
    winreg = None

import ctypes
from ctypes import wintypes

# ==============================================================================
# Constants & Cryptographic Hashes
# ==============================================================================

ORIGINAL_SHA256         = "00833fae4d5d70213158a146ca98439b28a8e962b934885ecccd906204880af2"
PATCHED_NET_3P_SHA256   = "8c4209a456b6ca1614294346ffd56c02e13dfc49bbb2bffaab0a538e130e8a4c"
PATCHED_NET_4P_SHA256   = "af35f180bb657cb50fe8a2bbc88d34f289a81ab0aa84b07bd5fc68a57896b069"
PATCHED_DUAL_3P_SHA256  = "2d695933c9fb046b80c32de99d76d2e27c334f42b507cb104526b3583480f84f"
PATCHED_DUAL_4P_SHA256  = "68e39e009e4c347fd29bbd3375767ff8a517278bd91c66ac9cf00b0a2a02dc55"
PATCHED_TRI_V1_3P_SHA256 = "995c5815a394d89b0120fa18587503c4ff51375645f99a30faf87727b075f243"
PATCHED_TRI_V1_4P_SHA256 = "7a5fd4b77938dbe0a87f38c37c6b875aefd307fdbfbefe4b0c9d139eac72b34d"
PATCHED_TRI_3P_SHA256   = "3fa1b2a5b926be1d0b9919fdd356316840c75072beb68e889adb873ac6193ae1"
PATCHED_TRI_4P_SHA256   = "39e317cfa0dcbc7adcdf794fd57ce616066f046f6c00afe8a12b2b2c32c76743"

# Gate 1: Network Session Capacity (mov eax, N)
NET_CAPACITY_RVA    = 0xa1a514a
NET_CAPACITY_OFFSET = 0xa1a434a
ORIGINAL_NET_BYTES  = bytes.fromhex("b802000000")

# Gate 2: Party Capacity Thunk (GetMaxPartySizeForGameMode)
PARTY_CAPACITY_RVA    = 0xa7fba0
PARTY_CAPACITY_OFFSET = 0xa7f1a0
ORIGINAL_PARTY_BYTES  = bytes.fromhex("e99bb35707cccccccccccccccccccccccccccccc")

# Gate 3: GameMode & Session Public Slot Capacity Allocation
SESSION_CAPACITY_RVA    = 0x948270
SESSION_CAPACITY_OFFSET = 0x947870
ORIGINAL_SESSION_BYTES  = bytes.fromhex("e95b160f07" + "cc" * 28)

# Legacy Milestone 9 Gate 3a / 3b locations (reverted during upgrades)
LEGACY_G3A_OFFSET = 0x92a325
LEGACY_G3A_ORIGINAL_BYTES = bytes.fromhex("0fb642594188455c")
LEGACY_G3B_OFFSET = 0xa7f175
LEGACY_G3B_ORIGINAL_BYTES = bytes.fromhex("cc" * 15)

# Expected PE Architecture Details
EXPECTED_MACHINE = 0x8664  # AMD64
EXPECTED_SIZEOFIMAGE = 0xeea9000

# Capacity Tiers
CAPACITY_CONFIG = {
    3: {
        "tier": "VERIFIED",
        "badge": "Tested & Proven",
        "description": "Full campaign co-op verified in live gameplay with 3 participants.",
        "color": "#28a745",  # Green
    },
    4: {
        "tier": "EXPERIMENTAL",
        "badge": "Experimental",
        "description": "Tri-Gate synchronized for 4 players. Backend supported, experimental.",
        "color": "#fd7e14",  # Orange
    },
}

for _n in range(5, 17):
    CAPACITY_CONFIG[_n] = {
        "tier": "EXPERIMENTAL",
        "badge": "Untested / Experimental",
        "description": f"Tri-Gate synchronized for {_n} players. Untested, subject to engine mesh replication limits.",
        "color": "#6c757d",  # Gray
    }

# Precomputed Known Tri-Gate Hashes (3 through 16)
KNOWN_TRI_HASHES: Dict[int, str] = {
    3:  "3fa1b2a5b926be1d0b9919fdd356316840c75072beb68e889adb873ac6193ae1",
    4:  "39e317cfa0dcbc7adcdf794fd57ce616066f046f6c00afe8a12b2b2c32c76743",
    5:  "ca0e6ffc8ecacef90771d5265a33492a2ade99e27b83d78da6aea925941ead17",
    6:  "20bdb02051348c8fb9bfbfbf8b1e77362f7ceb03535ef70bb95b4aa60c7d3264",
    7:  "d3447b18f58dc1d8cf5e4f56e73653dc3cf57b0aa134b51b6e854d14607f1bc7",
    8:  "c672c482fb7eff187a6f240f26718d443da685d60ada022d4e501a1c7b9d4c65",
    9:  "d7b61fe1ad92faa147aa03dcb83f051b6c86ed11df343cb8cac93ce92e97605e",
    10: "1514ee56f8a9006dacdaf4b782cf1d3fea45c42dfb39929ece4dd1aba093ce8b",
    11: "b742f53b9db59534dcdd463835f472ab15618519860c3160fc1369ad5d888f57",
    12: "eaa01b63f9dd0008f2dfd30423070b9e1245e6ea80ba98a92f407d20469271bb",
    13: "73d7a61339f2b68cf751509e92c2a210e5402c07ccf8cfc340e3614a930765fa",
    14: "cbbb8a7912b450b466af765f033346dc8c267ddc51629cbc83bf7d5a1b5b466d",
    15: "8d8046c9f161de358eb37e0d2a46cb4c7e53ff4a0e04ecf71082eda7f0e7207a",
    16: "e7e43275cd1c40b259f47938f34cf65eb91e251d6f1e9869f5e6917f60550fff",
}

ALL_KNOWN_PATCHED_HASHES = {
    PATCHED_NET_3P_SHA256,
    PATCHED_NET_4P_SHA256,
    PATCHED_DUAL_3P_SHA256,
    PATCHED_DUAL_4P_SHA256,
    PATCHED_TRI_V1_3P_SHA256,
    PATCHED_TRI_V1_4P_SHA256,
    *KNOWN_TRI_HASHES.values(),
}

# ==============================================================================
# Helper Functions: Hashing & Byte Generation
# ==============================================================================

def get_file_sha256(path: Path) -> str:
    """Calculates SHA-256 of file in 1MB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def generate_tri_gate_bytes(players: int) -> Tuple[bytes, bytes, bytes]:
    """
    Generates exact synchronized Tri-Gate byte sequences for a given capacity N (3 <= N <= 16).
    Returns (gate1_bytes, gate2_bytes, gate3_bytes).
    """
    if not (3 <= players <= 16):
        raise ValueError(f"Player capacity {players} is outside supported range [3..16]")

    # Gate 1 (Network Session Capacity): mov eax, N (5 bytes)
    g1 = b"\xb8" + players.to_bytes(4, "little")

    # Gate 2 (Party System Capacity): thunk at 0xa7fba0 (20 bytes)
    # sub rsp, 28h; call 0x7ffaf40; cmp al, 2; jne +2; mov al, N; add rsp, 28h; ret
    g2 = (
        bytes.fromhex("4883ec28e897b357073c027502b0")
        + players.to_bytes(1, "little")
        + bytes.fromhex("4883c428c3")
    )

    # Gate 3 (GameMode & Session Public Slots): thunk at 0x948270 (33 bytes)
    # sub rsp, 28h; call 0x7a398d0; add rsp, 28h; test rax, rax; jz +14;
    # cmp byte ptr [rax + 59h], 2; jne +8; mov byte ptr [rax + 59h], N; mov byte ptr [rax + 5ah], N; ret
    g3 = (
        bytes.fromhex("4883ec28e857160f074883c4284885c0740e807859027508c64059")
        + players.to_bytes(1, "little")
        + bytes.fromhex("c6405a")
        + players.to_bytes(1, "little")
        + b"\xc3"
    )

    return g1, g2, g3

# ==============================================================================
# Process Inspection: Detection of Running Game
# ==============================================================================

TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]

def is_game_running(exe_name: str = "FarCry5.exe") -> bool:
    """Checks whether the Far Cry 5 executable is currently running."""
    k32 = ctypes.windll.kernel32
    h_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snap == -1:
        return False
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    found = False
    try:
        if k32.Process32FirstW(h_snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.lower() == exe_name.lower():
                    found = True
                    break
                if not k32.Process32NextW(h_snap, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(h_snap)
    return found

# ==============================================================================
# Game Installation Auto-Detection
# ==============================================================================

class InstallationInfo:
    def __init__(self, root_dir: Path, dll_path: Path, source: str, platform_hint: str):
        self.root_dir = root_dir
        self.dll_path = dll_path
        self.source = source
        self.platform_hint = platform_hint

    def __repr__(self):
        return f"<Installation {self.platform_hint} at {self.root_dir}>"

def detect_installations() -> List[InstallationInfo]:
    """
    Auto-detects Far Cry 5 installations via:
      1. Ubisoft Connect Registry keys
      2. Steam App Manifest / Registry keys
      3. Steam Library Folders
      4. Standard default installation drives
    """
    candidates: List[Tuple[Path, str, str]] = []

    # 1. Ubisoft Connect Registry
    if winreg:
        for hive, sub in [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs\1803"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Ubisoft\Launcher\Installs\1803"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Ubisoft\Launcher\Installs\1803"),
        ]:
            try:
                with winreg.OpenKey(hive, sub) as k:
                    val, _ = winreg.QueryValueEx(k, "InstallDir")
                    if val:
                        candidates.append((Path(val), "Ubisoft Registry", "Ubisoft Connect"))
            except OSError:
                pass

    # 2. Steam App Uninstall Registry
    if winreg:
        for hive, sub in [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 552520"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 552520"),
        ]:
            try:
                with winreg.OpenKey(hive, sub) as k:
                    val, _ = winreg.QueryValueEx(k, "InstallLocation")
                    if val:
                        candidates.append((Path(val), "Steam Uninstall Registry", "Steam"))
            except OSError:
                pass

    # 3. Steam Library Folders
    if winreg:
        for hive, sub in [
            (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
        ]:
            try:
                with winreg.OpenKey(hive, sub) as k:
                    val, _ = winreg.QueryValueEx(k, "SteamPath")
                    if not val:
                        val, _ = winreg.QueryValueEx(k, "InstallPath")
                    if val:
                        sp = Path(val)
                        vdf = sp / "steamapps" / "libraryfolders.vdf"
                        if vdf.exists():
                            try:
                                text = vdf.read_text(encoding="utf-8", errors="ignore")
                                for line in text.splitlines():
                                    line = line.strip()
                                    if '"path"' in line:
                                        parts = line.split('"')
                                        if len(parts) >= 4:
                                            lib = Path(parts[3])
                                            fc5 = lib / "steamapps" / "common" / "Far Cry 5"
                                            candidates.append((fc5, "Steam Library VDF", "Steam"))
                            except Exception:
                                pass
            except OSError:
                pass

    # 4. Standard Game Paths
    standard_drives = ["S:", "C:", "D:", "E:", "F:", "G:"]
    for drive in standard_drives:
        candidates.append((Path(f"{drive}/Games/Far Cry 5"), f"Games Path ({drive})", "Manual/Standard"))
        candidates.append((Path(f"{drive}/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/games/Far Cry 5"), f"Ubisoft Default ({drive})", "Ubisoft Connect"))
        candidates.append((Path(f"{drive}/Program Files (x86)/Steam/steamapps/common/Far Cry 5"), f"Steam Default ({drive})", "Steam"))
        candidates.append((Path(f"{drive}/SteamLibrary/steamapps/common/Far Cry 5"), f"SteamLibrary ({drive})", "Steam"))

    results: List[InstallationInfo] = []
    seen = set()

    for path, source, platform in candidates:
        try:
            if not path.exists():
                continue
            resolved = str(path.resolve()).lower()
            if resolved in seen:
                continue
            seen.add(resolved)

            dll = path / "bin" / "FC_m64.dll"
            if dll.exists():
                results.append(InstallationInfo(path, dll, source, platform))
        except (OSError, PermissionError):
            continue

    return results

# ==============================================================================
# Binary & PE Validation
# ==============================================================================

def validate_pe_structure(dll_path: Path) -> Dict[str, Any]:
    """
    Validates PE structure, headers, and section properties of FC_m64.dll.
    Ensures the file is a genuine 64-bit Far Cry 5 binary.
    """
    info = {
        "valid": False,
        "machine": 0,
        "sections_count": 0,
        "xpdata_found": False,
        "error": "",
    }
    try:
        with open(dll_path, "rb") as f:
            dos_hdr = f.read(0x40)
            if len(dos_hdr) < 0x40 or dos_hdr[:2] != b"MZ":
                info["error"] = "Invalid DOS header magic (not an MZ executable)"
                return info

            e_lfanew = struct.unpack("<I", dos_hdr[0x3c:0x40])[0]
            if e_lfanew > 0x1000:
                info["error"] = f"e_lfanew offset too large (0x{e_lfanew:x})"
                return info

            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                info["error"] = "Invalid PE signature"
                return info

            file_hdr = f.read(20)
            machine, num_sections = struct.unpack("<HH", file_hdr[:4])
            info["machine"] = machine
            info["sections_count"] = num_sections

            if machine != EXPECTED_MACHINE:
                info["error"] = f"Unsupported architecture machine: 0x{machine:x} (expected AMD64 0x8664)"
                return info

            # Read Optional Header
            opt_hdr = f.read(240)
            if len(opt_hdr) < 240:
                info["error"] = "Optional header truncated"
                return info

            # Check sections
            for _ in range(num_sections):
                sec_hdr = f.read(40)
                if len(sec_hdr) < 40:
                    break
                sec_name = sec_hdr[:8].rstrip(b"\x00").decode("latin1", errors="ignore")
                if sec_name == ".xpdata":
                    info["xpdata_found"] = True

            info["valid"] = True
            return info

    except Exception as e:
        info["error"] = str(e)
        return info

def inspect_binary(dll_path: Path) -> Dict[str, Any]:
    """
    Thoroughly inspects binary state, SHA-256 hash, gate byte patterns,
    detected capacity, backup status, and running process state.
    """
    if not dll_path.exists():
        return {
            "exists": False,
            "status": "NOT_FOUND",
            "message": f"File not found: {dll_path}",
            "sha256": None,
            "capacity": None,
            "backup_exists": False,
            "backup_valid": False,
            "game_running": is_game_running(),
        }

    game_running = is_game_running()
    pe_info = validate_pe_structure(dll_path)
    file_sha256 = get_file_sha256(dll_path)

    # Read current gate bytes
    with open(dll_path, "rb") as f:
        f.seek(NET_CAPACITY_OFFSET)
        current_g1 = f.read(5)
        f.seek(PARTY_CAPACITY_OFFSET)
        current_g2 = f.read(20)
        f.seek(SESSION_CAPACITY_OFFSET)
        current_g3 = f.read(33)

    # Backup inspection
    backup_path = dll_path.with_name("FC_m64.dll.bak")
    backup_exists = backup_path.exists()
    backup_valid = False
    backup_sha = None
    if backup_exists:
        backup_sha = get_file_sha256(backup_path)
        backup_valid = (backup_sha == ORIGINAL_SHA256)

    # Identify binary state
    status = "UNKNOWN_MODIFIED"
    detected_cap = None
    message = "Binary modified with unrecognized content"

    if file_sha256 == ORIGINAL_SHA256 and current_g1 == ORIGINAL_NET_BYTES and current_g2 == ORIGINAL_PARTY_BYTES and current_g3 == ORIGINAL_SESSION_BYTES:
        status = "ORIGINAL_PRISTINE"
        detected_cap = 2
        message = "Official Pristine 2-Player Far Cry 5 Binary"

    # Check for known Tri-Gate builds
    elif file_sha256 in KNOWN_TRI_HASHES.values():
        for cap, h in KNOWN_TRI_HASHES.items():
            if file_sha256 == h:
                detected_cap = cap
                exp_g1, exp_g2, exp_g3 = generate_tri_gate_bytes(cap)
                if current_g1 == exp_g1 and current_g2 == exp_g2 and current_g3 == exp_g3:
                    status = "PATCHED_TRI_GATE"
                    tier_info = CAPACITY_CONFIG.get(cap, {})
                    message = f"Tri-Gate Patched for {cap} Players [{tier_info.get('badge', 'Active')}]"
                break

    elif file_sha256 == PATCHED_TRI_V1_3P_SHA256:
        status = "PATCHED_TRI_V1"
        detected_cap = 3
        message = "Tri-Gate v1 Patched (Needs upgrade to v2 for effective Session capacity)"

    elif file_sha256 in (PATCHED_DUAL_3P_SHA256, PATCHED_DUAL_4P_SHA256):
        status = "PATCHED_DUAL_GATE"
        detected_cap = 3 if file_sha256 == PATCHED_DUAL_3P_SHA256 else 4
        message = f"Dual-Gate Patched ({detected_cap} Players - Upgradable to Tri-Gate)"

    elif file_sha256 in (PATCHED_NET_3P_SHA256, PATCHED_NET_4P_SHA256):
        status = "PATCHED_NET_ONLY"
        detected_cap = 3 if file_sha256 == PATCHED_NET_3P_SHA256 else 4
        message = f"Network-Only Patched ({detected_cap} Players - Upgradable to Tri-Gate)"

    else:
        # Check if gate bytes correspond to any capacity N even if hash differs (e.g. slight metadata diff)
        for cap in range(3, 17):
            exp_g1, exp_g2, exp_g3 = generate_tri_gate_bytes(cap)
            if current_g1 == exp_g1 and current_g2 == exp_g2 and current_g3 == exp_g3:
                status = "PATCHED_CUSTOM_TRI"
                detected_cap = cap
                message = f"Custom Tri-Gate Patched ({cap} Players)"
                break

    return {
        "exists": True,
        "dll_path": dll_path,
        "status": status,
        "sha256": file_sha256,
        "capacity": detected_cap,
        "message": message,
        "pe_valid": pe_info.get("valid", False),
        "pe_info": pe_info,
        "backup_exists": backup_exists,
        "backup_valid": backup_valid,
        "backup_sha": backup_sha,
        "game_running": game_running,
        "g1_bytes": current_g1.hex(),
        "g2_bytes": current_g2.hex(),
        "g3_bytes": current_g3.hex(),
    }

# ==============================================================================
# Patch Application and Restoration
# ==============================================================================

def apply_patch(
    target_dll: Path,
    players: int = 3,
    force: bool = False,
    callback: Optional[Callable[[str, str], None]] = None,
) -> bool:
    """
    Applies the synchronized Tri-Gate capacity patch for N players (3 <= N <= 16).
    Enforces process detection, backup verification, atomic file replacement, and SHA-256 checks.
    """
    def log(msg: str, level: str = "INFO"):
        if callback:
            callback(msg, level)
        else:
            print(f"[{level}] {msg}")

    log(f"Initiating Tri-Gate patch operation for {players} players...", "INFO")

    # 1. Process safety check
    if is_game_running():
        log("REFUSED: FarCry5.exe is currently running! Please close the game before patching.", "ERROR")
        return False

    if not target_dll.exists():
        log(f"REFUSED: Target DLL does not exist at {target_dll}", "ERROR")
        return False

    # 2. Inspect state
    info = inspect_binary(target_dll)
    if not info["pe_valid"]:
        log(f"REFUSED: Target file is not a valid Far Cry 5 64-bit PE binary ({info['pe_info'].get('error')})", "ERROR")
        return False

    initial_sha = info["sha256"]
    log(f"Target binary: {target_dll}", "INFO")
    log(f"Current SHA-256: {initial_sha}", "INFO")
    log(f"Detected Status: {info['status']} ({info['message']})", "INFO")

    target_g1, target_g2, target_g3 = generate_tri_gate_bytes(players)
    expected_patch_hash = KNOWN_TRI_HASHES.get(players)

    # 3. Idempotency check: Already patched to requested capacity
    if (
        info["status"] == "PATCHED_TRI_GATE"
        and info["capacity"] == players
        and initial_sha == expected_patch_hash
    ):
        log(f"No-op: Target is already verified Tri-Gate patched for {players} players. Binary is unchanged.", "SUCCESS")
        return True

    # 4. Binary eligibility verification
    is_pristine = (initial_sha == ORIGINAL_SHA256)
    is_known_patched = (
        initial_sha in ALL_KNOWN_PATCHED_HASHES
        or info["status"].startswith("PATCHED_")
    )

    if not is_pristine and not is_known_patched and not force:
        log("REFUSED: Target binary contains unrecognized modifications or is an incompatible version.", "ERROR")
        log(f"Expected pristine SHA-256: {ORIGINAL_SHA256}", "ERROR")
        log(f"Actual SHA-256:            {initial_sha}", "ERROR")
        log("Patch aborted to protect game installation integrity.", "ERROR")
        return False

    # 5. Backup management
    backup_path = target_dll.with_name("FC_m64.dll.bak")
    if backup_path.exists():
        b_hash = get_file_sha256(backup_path)
        if b_hash != ORIGINAL_SHA256:
            log(f"REFUSED: Existing backup at {backup_path} is corrupt (SHA-256: {b_hash})!", "ERROR")
            log("Aborting to prevent operating without a genuine pristine backup.", "ERROR")
            return False
        log(f"Verified intact pristine backup: {backup_path}", "INFO")
    else:
        if not is_pristine:
            log("REFUSED: Cannot create pristine backup because current binary is already modified and no backup exists.", "ERROR")
            return False
        log(f"Creating pristine backup at: {backup_path}", "INFO")
        temp_bak = backup_path.with_name(f"{backup_path.name}.{uuid.uuid4().hex}.tmp")
        try:
            shutil.copy2(target_dll, temp_bak)
            if get_file_sha256(temp_bak) != ORIGINAL_SHA256:
                temp_bak.unlink(missing_ok=True)
                log("REFUSED: Backup copy failed cryptographic verification. Aborting.", "ERROR")
                return False
            os.replace(temp_bak, backup_path)
            log("Pristine backup created and verified successfully.", "SUCCESS")
        except Exception as e:
            if temp_bak.exists():
                temp_bak.unlink(missing_ok=True)
            log(f"Backup creation failed: {e}", "ERROR")
            return False

    # 6. Apply Tri-Gate patch in atomic temporary file on same volume
    temp_dest = target_dll.with_name(f"{target_dll.name}.{uuid.uuid4().hex}.tmp")
    try:
        data = bytearray(target_dll.read_bytes())

        # Gate 1: Network Core
        data[NET_CAPACITY_OFFSET:NET_CAPACITY_OFFSET + len(target_g1)] = target_g1
        # Gate 2: Party Thunk
        data[PARTY_CAPACITY_OFFSET:PARTY_CAPACITY_OFFSET + len(target_g2)] = target_g2
        # Gate 3: GameMode & Session Slots
        data[SESSION_CAPACITY_OFFSET:SESSION_CAPACITY_OFFSET + len(target_g3)] = target_g3

        # Revert any legacy Gate 3a / 3b locations from Milestone 9 v1
        data[LEGACY_G3A_OFFSET:LEGACY_G3A_OFFSET + len(LEGACY_G3A_ORIGINAL_BYTES)] = LEGACY_G3A_ORIGINAL_BYTES
        data[LEGACY_G3B_OFFSET:LEGACY_G3B_OFFSET + len(LEGACY_G3B_ORIGINAL_BYTES)] = LEGACY_G3B_ORIGINAL_BYTES

        temp_dest.write_bytes(data)

        # Verify temporary file
        temp_hash = get_file_sha256(temp_dest)
        if expected_patch_hash and temp_hash != expected_patch_hash:
            raise ValueError(f"Temporary patched binary hash mismatch! Got {temp_hash}, expected {expected_patch_hash}")

        # Atomic commit
        os.replace(temp_dest, target_dll)

    except Exception as e:
        if temp_dest.exists():
            temp_dest.unlink(missing_ok=True)
        log(f"Patch operation failed: {e}", "ERROR")
        log("Original installation preserved untouched.", "INFO")
        return False

    final_hash = get_file_sha256(target_dll)
    tier_info = CAPACITY_CONFIG.get(players, {})
    log(f"Tri-Gate Patch successfully applied for {players} players!", "SUCCESS")
    log(f"Status: {tier_info.get('badge', 'Applied')} — {tier_info.get('description', '')}", "INFO")
    log(f"New SHA-256: {final_hash}", "INFO")
    return True

def restore_original(
    target_dll: Path,
    force: bool = False,
    callback: Optional[Callable[[str, str], None]] = None,
) -> bool:
    """
    Restores the Far Cry 5 binary to official pristine original 2-player state.
    Prefers verified pristine .bak backup; falls back to in-place byte reversion if backup is missing.
    """
    def log(msg: str, level: str = "INFO"):
        if callback:
            callback(msg, level)
        else:
            print(f"[{level}] {msg}")

    log("Initiating restoration to original pristine state...", "INFO")

    if is_game_running():
        log("REFUSED: FarCry5.exe is currently running! Please close the game before restoring.", "ERROR")
        return False

    if not target_dll.exists():
        log(f"REFUSED: Target DLL does not exist at {target_dll}", "ERROR")
        return False

    current_hash = get_file_sha256(target_dll)
    if current_hash == ORIGINAL_SHA256:
        log("No-op: Target binary is already pristine original. No restoration needed.", "SUCCESS")
        return True

    is_known = (current_hash in ALL_KNOWN_PATCHED_HASHES)
    if not is_known and not force:
        log(f"REFUSED: Target contains unrecognized modifications (SHA-256: {current_hash}).", "ERROR")
        log("Restoration aborted to prevent data loss. Pass force=True to overwrite.", "ERROR")
        return False

    backup_path = target_dll.with_name("FC_m64.dll.bak")
    restored = False

    # Attempt restoration via verified pristine backup
    if backup_path.exists():
        b_hash = get_file_sha256(backup_path)
        if b_hash == ORIGINAL_SHA256:
            log(f"Restoring from verified pristine backup: {backup_path}", "INFO")
            temp_dest = target_dll.with_name(f"{target_dll.name}.{uuid.uuid4().hex}.tmp")
            try:
                shutil.copy2(backup_path, temp_dest)
                if get_file_sha256(temp_dest) != ORIGINAL_SHA256:
                    raise ValueError("Temporary copy failed integrity check")
                os.replace(temp_dest, target_dll)
                restored = True
                log("Binary restored from pristine backup successfully.", "SUCCESS")
            except Exception as e:
                if temp_dest.exists():
                    temp_dest.unlink(missing_ok=True)
                log(f"Backup restoration failed: {e}", "ERROR")
                return False
        else:
            log(f"Backup file exists but failed verification (Hash: {b_hash}).", "WARNING")

    # In-place byte restoration if backup unavailable or corrupt
    if not restored:
        if not is_known:
            log("REFUSED: Cannot restore in-place without a verified pristine backup for unrecognized builds.", "ERROR")
            return False

        log("Reverting Tri-Gate bytes in-place to original pristine state...", "INFO")
        temp_dest = target_dll.with_name(f"{target_dll.name}.{uuid.uuid4().hex}.tmp")
        try:
            data = bytearray(target_dll.read_bytes())
            data[NET_CAPACITY_OFFSET:NET_CAPACITY_OFFSET + len(ORIGINAL_NET_BYTES)] = ORIGINAL_NET_BYTES
            data[PARTY_CAPACITY_OFFSET:PARTY_CAPACITY_OFFSET + len(ORIGINAL_PARTY_BYTES)] = ORIGINAL_PARTY_BYTES
            data[SESSION_CAPACITY_OFFSET:SESSION_CAPACITY_OFFSET + len(ORIGINAL_SESSION_BYTES)] = ORIGINAL_SESSION_BYTES
            data[LEGACY_G3A_OFFSET:LEGACY_G3A_OFFSET + len(LEGACY_G3A_ORIGINAL_BYTES)] = LEGACY_G3A_ORIGINAL_BYTES
            data[LEGACY_G3B_OFFSET:LEGACY_G3B_OFFSET + len(LEGACY_G3B_ORIGINAL_BYTES)] = LEGACY_G3B_ORIGINAL_BYTES

            temp_dest.write_bytes(data)
            temp_hash = get_file_sha256(temp_dest)
            if temp_hash != ORIGINAL_SHA256:
                raise ValueError(f"Restored file hash mismatch: {temp_hash}")

            os.replace(temp_dest, target_dll)
            log("In-place restoration completed and verified 100% identical to pristine build.", "SUCCESS")
        except Exception as e:
            if temp_dest.exists():
                temp_dest.unlink(missing_ok=True)
            log(f"In-place restoration failed: {e}", "ERROR")
            return False

    final_hash = get_file_sha256(target_dll)
    log(f"Restoration Complete. Current SHA-256: {final_hash}", "SUCCESS")
    return True
