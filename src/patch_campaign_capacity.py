#!/usr/bin/env python3
"""
Far Cry 5 3-Player Co-op — Hardened Tri-Gate Campaign Capacity Patch Tool
Applies, verifies, and restores the synchronized 3-player (or 4-player) Tri-Gate patch in bin/FC_m64.dll.

Tri-Gate Architecture:
  Gate 1 (Network Session Target Capacity):
    RVA: 0xa1a514a (File offset: 0xa1a434a, 5 bytes)
    Pristine: mov eax, 2 (b8 02 00 00 00)
    Patched:  mov eax, N (b8 03 00 00 00 / b8 04 00 00 00)
    Governs public session slots in CFCXGameModeCoop_Setup -> CreateSession.

  Gate 2 (Party System Capacity):
    RVA: 0xa7fba0 (File offset: 0xa7f1a0, 20 bytes)
    Pristine: jmp 0x7ffaf40; 15x int3 (e9 9b b3 57 07 cc...cc)
    Patched:  sub rsp, 0x28; call 0x7ffaf40; cmp al, 2; jne +2; mov al, N; add rsp, 0x28; ret
              (48 83 ec 28 e8 97 b3 57 07 3c 02 75 02 b0 0N 48 83 c4 28 c3)
    Governs GetMaxPartySizeForGameMode thunk -> Party::SetPartyLimit.
    Eliminates Bookworm-E4691238 ("Party full, refuse join request") while preserving Solo and Arcade.

  Gate 3 (GameMode & Session Public Slot Capacity Allocation):
    RVA: 0x948270 (File offset: 0x947870, 33 bytes in thunk + padding)
    Pristine: jmp 0x7a398d0; 28x int3 (e9 5b 16 0f 07 cc...cc)
    Patched:  sub rsp, 0x28; call 0x7a398d0; add rsp, 0x28; test rax, rax; jz +14;
              cmp byte ptr [rax + 0x59], 2; jne +8;
              mov byte ptr [rax + 0x59], N; mov byte ptr [rax + 0x5a], N; ret
              (48 83 ec 28 e8 57 16 0f 07 48 83 c4 28 48 85 c0 74 0e 80 78 59 02 75 08 c6 40 59 0N c6 40 5a 0N c3)
    Governs GameModeManager::GetGameModeDescriptor -> sets MaxPlayers=N, MaxPartySize=N on GameModeDescriptor.
    Propagates directly to:
      1. Session::Initialize (RVA 0x7db22e0):
         - MaxPlayers/MaxPartySize = N/N = 1 team (team[0].capacity = N)
         - Session + 0x2f0 = 1 (FilledSlots)
         - Session + 0x2f1 = 0 (ReservedSlots)
         - Session + 0x2f2 = N (MaxSlots)
      2. Session::CheckSpace (RVA 0xa1b557):
         Available = N - 0 - 2 = 1 >= 1 (Admitting 3rd participant at Site A).
      3. CreateSession (RVA 0x7ba53b1) and backend Ubisoft/Storm lobby (Property ID 4 = N).

Safety guarantees:
  1. Enforces strict full-file SHA-256 verification before applying any patch.
  2. Verifies that backup files are genuinely pristine before relying on them.
  3. Writes and validates patched binaries in a temporary file before atomic replacement.
  4. Restricts restoration exclusively to known-state binaries and verified pristine backups.
  5. Preserves unrecognized binary modifications during restoration unless explicitly approved via --force.
  6. Rejects 'copy --output' paths that resolve to the target binary or its backup.
  7. Supports seamless upgrades from legacy Network-Only, Dual-Gate, and Tri-Gate v1 patches to full Tri-Gate v2.
  8. Preserves original file untouched if any step or assertion fails.
"""

import os
import sys
import uuid
import shutil
import hashlib
import argparse
from pathlib import Path

try:
    import pefile
    import capstone
except ImportError:
    print("Error: pefile and capstone are required. Please install them in the Python environment.")
    sys.exit(1)

DEFAULT_BIN = Path(r"S:\Games\Far Cry 5\bin\FC_m64.dll")

# Cryptographic Signatures
ORIGINAL_SHA256         = "00833fae4d5d70213158a146ca98439b28a8e962b934885ecccd906204880af2"
PATCHED_NET_3P_SHA256   = "8c4209a456b6ca1614294346ffd56c02e13dfc49bbb2bffaab0a538e130e8a4c"
PATCHED_NET_4P_SHA256   = "af35f180bb657cb50fe8a2bbc88d34f289a81ab0aa84b07bd5fc68a57896b069"
PATCHED_DUAL_3P_SHA256  = "2d695933c9fb046b80c32de99d76d2e27c334f42b507cb104526b3583480f84f"
PATCHED_DUAL_4P_SHA256  = "68e39e009e4c347fd29bbd3375767ff8a517278bd91c66ac9cf00b0a2a02dc55"
PATCHED_TRI_V1_3P_SHA256 = "995c5815a394d89b0120fa18587503c4ff51375645f99a30faf87727b075f243"
PATCHED_TRI_V1_4P_SHA256 = "7a5fd4b77938dbe0a87f38c37c6b875aefd307fdbfbefe4b0c9d139eac72b34d"
PATCHED_TRI_3P_SHA256   = "3fa1b2a5b926be1d0b9919fdd356316840c75072beb68e889adb873ac6193ae1"
PATCHED_TRI_4P_SHA256   = "39e317cfa0dcbc7adcdf794fd57ce616066f046f6c00afe8a12b2b2c32c76743"

# Default aliases
PATCHED_3P_SHA256 = PATCHED_TRI_3P_SHA256
PATCHED_4P_SHA256 = PATCHED_TRI_4P_SHA256

KNOWN_PATCHED_HASHES = {
    PATCHED_NET_3P_SHA256,
    PATCHED_NET_4P_SHA256,
    PATCHED_DUAL_3P_SHA256,
    PATCHED_DUAL_4P_SHA256,
    PATCHED_TRI_V1_3P_SHA256,
    PATCHED_TRI_V1_4P_SHA256,
    PATCHED_TRI_3P_SHA256,
    PATCHED_TRI_4P_SHA256,
}

# Gate 1: Network Session Capacity (mov eax, N)
NET_CAPACITY_RVA    = 0xa1a514a
NET_CAPACITY_OFFSET = 0xa1a434a
ORIGINAL_NET_BYTES   = bytes.fromhex("b802000000")
PATCHED_3P_NET_BYTES = bytes.fromhex("b803000000")
PATCHED_4P_NET_BYTES = bytes.fromhex("b804000000")

# Gate 2: Party Capacity Thunk (GetMaxPartySizeForGameMode)
PARTY_CAPACITY_RVA    = 0xa7fba0
PARTY_CAPACITY_OFFSET = 0xa7f1a0
ORIGINAL_PARTY_BYTES   = bytes.fromhex("e99bb35707cccccccccccccccccccccccccccccc")
PATCHED_3P_PARTY_BYTES = bytes.fromhex("4883ec28e897b357073c027502b0034883c428c3")
PATCHED_4P_PARTY_BYTES = bytes.fromhex("4883ec28e897b357073c027502b0044883c428c3")

# Gate 3: GameMode & Session Public Slot Capacity Allocation
SESSION_CAPACITY_RVA    = 0x948270
SESSION_CAPACITY_OFFSET = 0x947870
ORIGINAL_SESSION_BYTES   = bytes.fromhex("e95b160f07" + "cc" * 28)
PATCHED_3P_SESSION_BYTES = bytes.fromhex("4883ec28e857160f074883c4284885c0740e807859027508c6405903c6405a03c3")
PATCHED_4P_SESSION_BYTES = bytes.fromhex("4883ec28e857160f074883c4284885c0740e807859027508c6405904c6405a04c3")

# Legacy Milestone 9 Gate 3a / 3b locations (reverted during upgrades)
LEGACY_G3A_OFFSET = 0x92a325
LEGACY_G3A_ORIGINAL_BYTES = bytes.fromhex("0fb642594188455c")
LEGACY_G3B_OFFSET = 0xa7f175
LEGACY_G3B_ORIGINAL_BYTES = bytes.fromhex("cc" * 15)

# Aliases for backwards compatibility with tests
TARGET_RVA         = NET_CAPACITY_RVA
TARGET_FILE_OFFSET = NET_CAPACITY_OFFSET
ORIGINAL_BYTES     = ORIGINAL_NET_BYTES
PATCHED_3P_BYTES   = PATCHED_3P_NET_BYTES
PATCHED_4P_BYTES   = PATCHED_4P_NET_BYTES

def get_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def disassemble_bytes(data_bytes: bytes, rva: int) -> list[str]:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines = []
    for ins in md.disasm(data_bytes, rva):
        lines.append(f"0x{ins.address:x}: {ins.bytes.hex():<16} {ins.mnemonic} {ins.op_str}")
    return lines

def disassemble_at(data_bytes: bytes, rva: int) -> str:
    lines = disassemble_bytes(data_bytes, rva)
    return " | ".join(lines) if lines else "unable to disassemble"

def check_status(target: Path) -> dict:
    if not target.exists():
        return {
            "status": "NOT_FOUND",
            "sha256": None,
            "instruction": None,
            "bytes": None,
            "net_instruction": None,
            "net_bytes": None,
            "party_instruction": None,
            "party_bytes": None,
            "session_instruction": None,
            "session_bytes": None,
        }

    actual_hash = get_file_sha256(target)

    with open(target, "rb") as f:
        f.seek(NET_CAPACITY_OFFSET)
        current_net_bytes = f.read(len(ORIGINAL_NET_BYTES))
        f.seek(PARTY_CAPACITY_OFFSET)
        current_party_bytes = f.read(len(ORIGINAL_PARTY_BYTES))
        f.seek(SESSION_CAPACITY_OFFSET)
        current_sess_bytes = f.read(len(ORIGINAL_SESSION_BYTES))

    disasm_net = disassemble_at(current_net_bytes, NET_CAPACITY_RVA)
    disasm_party = disassemble_at(current_party_bytes, PARTY_CAPACITY_RVA)
    disasm_sess = disassemble_at(current_sess_bytes, SESSION_CAPACITY_RVA)

    if (actual_hash == ORIGINAL_SHA256 and
        current_net_bytes == ORIGINAL_NET_BYTES and
        current_party_bytes == ORIGINAL_PARTY_BYTES and
        current_sess_bytes == ORIGINAL_SESSION_BYTES):
        state = "ORIGINAL_PRISTINE (2 Players)"
    elif (actual_hash == PATCHED_TRI_3P_SHA256 and
          current_net_bytes == PATCHED_3P_NET_BYTES and
          current_party_bytes == PATCHED_3P_PARTY_BYTES and
          current_sess_bytes == PATCHED_3P_SESSION_BYTES):
        state = "PATCHED_TRI_GATE (3 Players - Gate 1, 2 & 3)"
    elif (actual_hash == PATCHED_TRI_4P_SHA256 and
          current_net_bytes == PATCHED_4P_NET_BYTES and
          current_party_bytes == PATCHED_4P_PARTY_BYTES and
          current_sess_bytes == PATCHED_4P_SESSION_BYTES):
        state = "PATCHED_TRI_GATE (4 Players - Gate 1, 2 & 3)"
    elif actual_hash == PATCHED_TRI_V1_3P_SHA256:
        state = "PATCHED_TRI_GATE_V1 (3 Players - Needs Upgrade)"
    elif actual_hash == PATCHED_TRI_V1_4P_SHA256:
        state = "PATCHED_TRI_GATE_V1 (4 Players - Needs Upgrade)"
    elif (actual_hash == PATCHED_DUAL_3P_SHA256 and
          current_net_bytes == PATCHED_3P_NET_BYTES and
          current_party_bytes == PATCHED_3P_PARTY_BYTES):
        state = "PATCHED_DUAL_GATE (3 Players - Gate 1 & 2)"
    elif (actual_hash == PATCHED_DUAL_4P_SHA256 and
          current_net_bytes == PATCHED_4P_NET_BYTES and
          current_party_bytes == PATCHED_4P_PARTY_BYTES):
        state = "PATCHED_DUAL_GATE (4 Players - Gate 1 & 2)"
    elif (actual_hash == PATCHED_NET_3P_SHA256 and
          current_net_bytes == PATCHED_3P_NET_BYTES and
          current_party_bytes == ORIGINAL_PARTY_BYTES):
        state = "PATCHED_NET_ONLY (3 Players - Gate 1 Only)"
    elif (actual_hash == PATCHED_NET_4P_SHA256 and
          current_net_bytes == PATCHED_4P_NET_BYTES and
          current_party_bytes == ORIGINAL_PARTY_BYTES):
        state = "PATCHED_NET_ONLY (4 Players - Gate 1 Only)"
    else:
        state = f"MODIFIED / CUSTOM (Net: {current_net_bytes.hex()}, Party: {current_party_bytes.hex()}, Sess: {current_sess_bytes[:10].hex()})"

    return {
        "status": state,
        "sha256": actual_hash,
        "instruction": disasm_net,
        "bytes": current_net_bytes.hex(),
        "net_instruction": disasm_net,
        "net_bytes": current_net_bytes.hex(),
        "party_instruction": disasm_party,
        "party_bytes": current_party_bytes.hex(),
        "session_instruction": disasm_sess,
        "session_bytes": current_sess_bytes.hex(),
    }

def print_status(target: Path):
    info = check_status(target)
    print(f"Target file: {target}")
    print(f"Status:      {info['status']}")
    print(f"SHA-256:     {info['sha256']}")
    if info.get('net_bytes'):
        print(f"\nGate 1 (Network Session Capacity - RVA 0x{NET_CAPACITY_RVA:x}):")
        print(f"  Bytes:       {info['net_bytes']}")
        print(f"  Disassembly: {info['net_instruction']}")
    if info.get('party_bytes'):
        print(f"\nGate 2 (Party System Capacity - RVA 0x{PARTY_CAPACITY_RVA:x}):")
        print(f"  Bytes:       {info['party_bytes']}")
        print(f"  Disassembly:")
        for line in disassemble_bytes(bytes.fromhex(info['party_bytes']), PARTY_CAPACITY_RVA):
            print(f"    {line}")
    if info.get('session_bytes'):
        print(f"\nGate 3 (GameMode & Session Public Slots Capacity - RVA 0x{SESSION_CAPACITY_RVA:x}):")
        print(f"  Bytes:       {info['session_bytes']}")
        print(f"  Disassembly:")
        for line in disassemble_bytes(bytes.fromhex(info['session_bytes']), SESSION_CAPACITY_RVA):
            print(f"    {line}")

def cmd_patch(target: Path, players: int = 3, in_place: bool = True, output_path: Path = None, dry_run: bool = False):
    if not target.exists():
        print(f"Error: Target file not found at {target}")
        sys.exit(1)

    print(f"[*] Reading target binary: {target}")
    initial_hash = get_file_sha256(target)

    with open(target, "rb") as f:
        f.seek(NET_CAPACITY_OFFSET)
        current_net_bytes = f.read(len(ORIGINAL_NET_BYTES))
        f.seek(PARTY_CAPACITY_OFFSET)
        current_party_bytes = f.read(len(ORIGINAL_PARTY_BYTES))
        f.seek(SESSION_CAPACITY_OFFSET)
        current_sess_bytes = f.read(len(ORIGINAL_SESSION_BYTES))

    print(f"[*] Current SHA-256: {initial_hash}")
    print(f"[*] Gate 1 bytes at 0x{NET_CAPACITY_OFFSET:x}: {current_net_bytes.hex()} ({disassemble_at(current_net_bytes, NET_CAPACITY_RVA)})")
    print(f"[*] Gate 2 bytes at 0x{PARTY_CAPACITY_OFFSET:x}: {current_party_bytes.hex()} ({disassemble_at(current_party_bytes, PARTY_CAPACITY_RVA)})")
    print(f"[*] Gate 3 bytes at 0x{SESSION_CAPACITY_OFFSET:x}: {current_sess_bytes[:10].hex()}... ({disassemble_at(current_sess_bytes, SESSION_CAPACITY_RVA)})")

    if 3 <= players <= 16:
        from patch_engine import generate_tri_gate_bytes, KNOWN_TRI_HASHES
        target_net_bytes, target_party_bytes, target_sess_bytes = generate_tri_gate_bytes(players)
        expected_patch_hash = KNOWN_TRI_HASHES.get(players)
    else:
        print(f"Error: Unsupported player count: {players}. Only capacities 3 through 16 are supported.")
        sys.exit(1)

    # Idempotency check: Already tri-patched
    if (initial_hash == expected_patch_hash and 
        current_net_bytes == target_net_bytes and 
        current_party_bytes == target_party_bytes and
        current_sess_bytes == target_sess_bytes):
        print(f"[!] Target binary is already verified Tri-Gate patched for {players} players. No changes required.")
        return

    # Verify origin state: Must be pristine or a recognized known patched build
    if initial_hash == ORIGINAL_SHA256:
        print(f"[*] Target is verified pristine original. Applying full Tri-Gate patch for {players} players...")
    elif initial_hash in (PATCHED_NET_3P_SHA256, PATCHED_NET_4P_SHA256):
        print(f"[*] Target has legacy Network-Only patch. Upgrading to full Tri-Gate patch for {players} players...")
    elif initial_hash in (PATCHED_DUAL_3P_SHA256, PATCHED_DUAL_4P_SHA256):
        print(f"[*] Target has Dual-Gate patch. Upgrading to full Tri-Gate patch for {players} players...")
    elif initial_hash in (PATCHED_TRI_V1_3P_SHA256, PATCHED_TRI_V1_4P_SHA256):
        print(f"[*] Target has Tri-Gate v1 patch. Upgrading to authoritative Tri-Gate v2 for {players} players...")
    elif initial_hash in (PATCHED_TRI_3P_SHA256, PATCHED_TRI_4P_SHA256):
        print(f"[*] Target is currently Tri-Gate patched for another capacity. Re-patching to {players} players...")
    else:
        print(f"[ERROR] Target binary SHA-256 does NOT match any recognized pristine or known patched build!")
        print(f"        Expected pristine: {ORIGINAL_SHA256}")
        print(f"        Actual:            {initial_hash}")
        print("Modification aborted to protect installation integrity.")
        sys.exit(1)

    # Determine destination and validate edge cases
    if in_place:
        dest = target
    else:
        dest = output_path or target.with_name(f"FC_m64.{players}player.dll")
        target_resolved = target.resolve()
        dest_resolved = dest.resolve()
        backup_resolved = target.with_name("FC_m64.dll.bak").resolve()

        if dest_resolved == target_resolved:
            print(f"[ERROR] 'copy --output' destination resolves to the target binary itself ({dest}).")
            print("        Refusing to overwrite target binary via copy command. Use 'patch' for in-place modifications.")
            sys.exit(1)
        if dest_resolved == backup_resolved:
            print(f"[ERROR] 'copy --output' destination resolves to the target backup file ({dest}).")
            print("        Refusing to overwrite backup file via copy command.")
            sys.exit(1)

    # Manage backup when patching in-place
    if in_place:
        backup_path = target.with_name("FC_m64.dll.bak")
        if backup_path.exists():
            b_hash = get_file_sha256(backup_path)
            if b_hash != ORIGINAL_SHA256:
                print(f"[ERROR] Existing backup at {backup_path} is corrupt (SHA-256: {b_hash}).")
                print("Aborting patch to prevent operating without a verified pristine backup.")
                sys.exit(1)
            print(f"[*] Verified existing pristine backup: {backup_path} (SHA-256: {b_hash})")
        else:
            if initial_hash != ORIGINAL_SHA256:
                print("[ERROR] Cannot create pristine backup because current target is not pristine.")
                sys.exit(1)
            print(f"[*] Creating verified pristine backup at: {backup_path}")
            if not dry_run:
                temp_bak = backup_path.with_name(f"{backup_path.name}.{uuid.uuid4().hex}.tmp")
                shutil.copy2(target, temp_bak)
                if get_file_sha256(temp_bak) != ORIGINAL_SHA256:
                    temp_bak.unlink(missing_ok=True)
                    print("[ERROR] Backup verification failed during copy. Aborting.")
                    sys.exit(1)
                os.replace(temp_bak, backup_path)
                print(f"    Backup verified and committed.")

    if dry_run:
        print(f"[DRY-RUN] Would tri-patch {target} -> {dest} for {players} players.")
        print(f"          Expected destination SHA-256: {expected_patch_hash}")
        return

    # Generate patched binary in temporary file on same volume for atomic replacement
    temp_dest = dest.with_name(f"{dest.name}.{uuid.uuid4().hex}.tmp")
    try:
        data = bytearray(target.read_bytes())
        # Apply Gate 1: Network session capacity (mov eax, N)
        data[NET_CAPACITY_OFFSET:NET_CAPACITY_OFFSET + len(target_net_bytes)] = target_net_bytes
        # Apply Gate 2: Party system capacity thunk
        data[PARTY_CAPACITY_OFFSET:PARTY_CAPACITY_OFFSET + len(target_party_bytes)] = target_party_bytes
        # Apply Gate 3: GameMode & Session Public Slot Capacity
        data[SESSION_CAPACITY_OFFSET:SESSION_CAPACITY_OFFSET + len(target_sess_bytes)] = target_sess_bytes

        # Revert any legacy Gate 3a / 3b locations from Milestone 9 v1
        data[LEGACY_G3A_OFFSET:LEGACY_G3A_OFFSET + len(LEGACY_G3A_ORIGINAL_BYTES)] = LEGACY_G3A_ORIGINAL_BYTES
        data[LEGACY_G3B_OFFSET:LEGACY_G3B_OFFSET + len(LEGACY_G3B_ORIGINAL_BYTES)] = LEGACY_G3B_ORIGINAL_BYTES

        temp_dest.write_bytes(data)

        # Rigorous verification of the temporary patched file
        temp_hash = get_file_sha256(temp_dest)
        if temp_hash != expected_patch_hash:
            raise ValueError(f"Temporary patched binary hash mismatch! Got {temp_hash}, expected {expected_patch_hash}")

        # Verify instructions in temp file
        with open(temp_dest, "rb") as f:
            f.seek(NET_CAPACITY_OFFSET)
            w_net = f.read(len(target_net_bytes))
            f.seek(PARTY_CAPACITY_OFFSET)
            w_party = f.read(len(target_party_bytes))
            f.seek(SESSION_CAPACITY_OFFSET)
            w_sess = f.read(len(target_sess_bytes))
            f.seek(LEGACY_G3A_OFFSET)
            w_g3a = f.read(len(LEGACY_G3A_ORIGINAL_BYTES))
            f.seek(LEGACY_G3B_OFFSET)
            w_g3b = f.read(len(LEGACY_G3B_ORIGINAL_BYTES))

        if w_net != target_net_bytes:
            raise ValueError(f"Gate 1 bytes mismatch in temp binary: got {w_net.hex()}, expected {target_net_bytes.hex()}")
        if w_party != target_party_bytes:
            raise ValueError(f"Gate 2 bytes mismatch in temp binary: got {w_party.hex()}, expected {target_party_bytes.hex()}")
        if w_sess != target_sess_bytes:
            raise ValueError(f"Gate 3 bytes mismatch in temp binary: got {w_sess.hex()}, expected {target_sess_bytes.hex()}")
        if w_g3a != LEGACY_G3A_ORIGINAL_BYTES:
            raise ValueError(f"Legacy G3a cleanup mismatch: got {w_g3a.hex()}, expected {LEGACY_G3A_ORIGINAL_BYTES.hex()}")
        if w_g3b != LEGACY_G3B_ORIGINAL_BYTES:
            raise ValueError(f"Legacy G3b cleanup mismatch: got {w_g3b.hex()}, expected {LEGACY_G3B_ORIGINAL_BYTES.hex()}")

        # Atomic commit
        os.replace(temp_dest, dest)

    except Exception as e:
        if temp_dest.exists():
            temp_dest.unlink(missing_ok=True)
        print(f"[ERROR] Patch failed: {e}")
        print("Original installation has been preserved.")
        sys.exit(1)

    final_hash = get_file_sha256(dest)
    print("\n[+] Tri-Gate Patch successfully applied and verified!")
    print(f"    Destination: {dest}")
    print(f"    New SHA-256: {final_hash}")
    print(f"    Gate 1 (Network Session Capacity): 0x{NET_CAPACITY_RVA:x}: {disassemble_at(target_net_bytes, NET_CAPACITY_RVA)}")
    print(f"    Gate 2 (Party Thunk Capacity):     0x{PARTY_CAPACITY_RVA:x}: {disassemble_at(target_party_bytes, PARTY_CAPACITY_RVA)}")
    print(f"    Gate 3 (GameMode & Session Slots): 0x{SESSION_CAPACITY_RVA:x}: {disassemble_at(target_sess_bytes, SESSION_CAPACITY_RVA)}")

def cmd_restore(target: Path, dry_run: bool = False, force: bool = False):
    if not target.exists():
        print(f"Error: Target file not found at {target}")
        sys.exit(1)

    current_hash = get_file_sha256(target)
    if current_hash == ORIGINAL_SHA256:
        print("[!] Target binary is already pristine original. No restoration needed.")
        return

    # Check if target binary has unrecognized modifications
    is_known_patched = current_hash in KNOWN_PATCHED_HASHES
    if not is_known_patched and not force:
        print(f"[ERROR] Target binary contains unrecognized modifications (SHA-256: {current_hash}).")
        print("        Restoration aborted to preserve existing modifications.")
        print("        To explicitly overwrite unrecognized modifications with pristine original, pass --force.")
        sys.exit(1)

    backup_path = target.with_name("FC_m64.dll.bak")
    restored_from_backup = False

    # Attempt restoration via verified pristine backup
    if backup_path.exists():
        b_hash = get_file_sha256(backup_path)
        if b_hash == ORIGINAL_SHA256:
            print(f"[*] Restoring from verified pristine backup: {backup_path}")
            if not dry_run:
                temp_dest = target.with_name(f"{target.name}.{uuid.uuid4().hex}.tmp")
                try:
                    shutil.copy2(backup_path, temp_dest)
                    if get_file_sha256(temp_dest) != ORIGINAL_SHA256:
                        raise ValueError("Temp restoration copy failed integrity check.")
                    os.replace(temp_dest, target)
                    restored_from_backup = True
                except Exception as e:
                    if temp_dest.exists():
                        temp_dest.unlink(missing_ok=True)
                    print(f"[ERROR] Backup restoration failed: {e}")
                    sys.exit(1)
            else:
                print(f"[DRY-RUN] Would restore {target} from {backup_path}.")
                return
        else:
            print(f"[WARNING] Backup file exists but failed integrity check (Hash: {b_hash}).")

    if not restored_from_backup and not dry_run:
        # If no verified backup exists, we can ONLY restore in-place if target is a known patched build
        if not is_known_patched:
            print(f"[ERROR] Cannot restore in-place: target binary has unrecognized modifications (SHA-256: {current_hash}) and no verified backup exists.")
            print("        Restoration requires a verified pristine backup to recover the original binary.")
            sys.exit(1)

        print(f"[*] Target is in known patched state ({current_hash[:16]}...). Reverting Tri-Gate instruction bytes in-place...")
        temp_dest = target.with_name(f"{target.name}.{uuid.uuid4().hex}.tmp")
        try:
            data = bytearray(target.read_bytes())
            data[NET_CAPACITY_OFFSET:NET_CAPACITY_OFFSET + len(ORIGINAL_NET_BYTES)] = ORIGINAL_NET_BYTES
            data[PARTY_CAPACITY_OFFSET:PARTY_CAPACITY_OFFSET + len(ORIGINAL_PARTY_BYTES)] = ORIGINAL_PARTY_BYTES
            data[SESSION_CAPACITY_OFFSET:SESSION_CAPACITY_OFFSET + len(ORIGINAL_SESSION_BYTES)] = ORIGINAL_SESSION_BYTES
            data[LEGACY_G3A_OFFSET:LEGACY_G3A_OFFSET + len(LEGACY_G3A_ORIGINAL_BYTES)] = LEGACY_G3A_ORIGINAL_BYTES
            data[LEGACY_G3B_OFFSET:LEGACY_G3B_OFFSET + len(LEGACY_G3B_ORIGINAL_BYTES)] = LEGACY_G3B_ORIGINAL_BYTES

            temp_dest.write_bytes(data)

            temp_hash = get_file_sha256(temp_dest)
            if temp_hash != ORIGINAL_SHA256:
                raise ValueError(f"Restored binary failed hash check (Got {temp_hash}, expected {ORIGINAL_SHA256}).")

            os.replace(temp_dest, target)
        except Exception as e:
            if temp_dest.exists():
                temp_dest.unlink(missing_ok=True)
            print(f"[ERROR] In-place restoration failed: {e}")
            sys.exit(1)

    final_hash = get_file_sha256(target)
    print("\n[+] Restoration complete!")
    print(f"    Current SHA-256: {final_hash}")
    if final_hash == ORIGINAL_SHA256:
        print("    Binary is verified 100% identical to pristine original build.")
    else:
        print(f"    [WARNING] Binary restored but hash does not match original: {final_hash}")

def main():
    parser = argparse.ArgumentParser(
        description="Far Cry 5 3-Player Co-op — Hardened Tri-Gate Campaign Capacity Patch Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/patch_campaign_capacity.py status
  python src/patch_campaign_capacity.py patch --players 3
  python src/patch_campaign_capacity.py patch --players 4
  python src/patch_campaign_capacity.py copy --players 3 --output FC_m64.3p.dll
  python src/patch_campaign_capacity.py restore
  python src/patch_campaign_capacity.py restore --force
        """
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    p_status = subparsers.add_parser("status", help="Inspect binary patch and capacity status")
    p_status.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BIN, help="Path to FC_m64.dll")

    # patch (in-place)
    p_patch = subparsers.add_parser("patch", help="Apply Tri-Gate patch in-place to target binary")
    p_patch.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BIN, help="Path to FC_m64.dll")
    p_patch.add_argument("--players", type=int, default=3, choices=list(range(3, 17)), help="Target player count (default: 3)")
    p_patch.add_argument("--dry-run", action="store_true", help="Simulate patch operation without writing files")

    # copy (out-of-place)
    p_copy = subparsers.add_parser("copy", help="Create a patched copy of the binary at a separate destination")
    p_copy.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BIN, help="Source path to pristine FC_m64.dll")
    p_copy.add_argument("--players", type=int, default=3, choices=list(range(3, 17)), help="Target player count (default: 3)")
    p_copy.add_argument("--output", type=Path, required=True, help="Destination output path")
    p_copy.add_argument("--dry-run", action="store_true", help="Simulate copy operation without writing files")

    # restore
    p_restore = subparsers.add_parser("restore", help="Restore binary to pristine original state")
    p_restore.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BIN, help="Path to FC_m64.dll")
    p_restore.add_argument("--dry-run", action="store_true", help="Simulate restoration operation without modifying binary")
    p_restore.add_argument("--force", action="store_true", help="Overwrite unrecognized modifications with pristine original")

    args = parser.parse_args()

    if args.command == "status":
        print_status(args.binary)
    elif args.command == "patch":
        cmd_patch(args.binary, players=args.players, in_place=True, dry_run=args.dry_run)
    elif args.command == "copy":
        cmd_patch(args.binary, players=args.players, in_place=False, output_path=args.output, dry_run=args.dry_run)
    elif args.command == "restore":
        cmd_restore(args.binary, dry_run=args.dry_run, force=args.force)

if __name__ == "__main__":
    main()
