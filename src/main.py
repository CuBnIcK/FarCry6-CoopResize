#!/usr/bin/env python3
"""
Far Cry 5 Campaign Co-op Patcher — Unified Standalone Entry Point
Supports both full graphical Windows GUI mode and automated CLI mode.
"""

import sys
import argparse
from pathlib import Path

import patch_engine as pe

def attach_console_if_cli():
    if len(sys.argv) > 1 and not (len(sys.argv) == 2 and sys.argv[1] == "--gui"):
        try:
            import ctypes
            if ctypes.windll.kernel32.AttachConsole(0xFFFFFFFF):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        except Exception:
            pass

def run_cli():
    attach_console_if_cli()
    parser = argparse.ArgumentParser(
        description="Far Cry 5 Campaign Co-op & Cutscene Camera Patcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  FC5CampaignCoopPatcher.exe
  FC5CampaignCoopPatcher.exe --status
  FC5CampaignCoopPatcher.exe --patch 3
  FC5CampaignCoopPatcher.exe --patch 3 --camera-fix
  FC5CampaignCoopPatcher.exe --camera-fix
  FC5CampaignCoopPatcher.exe --no-camera-fix
  FC5CampaignCoopPatcher.exe --restore
        """,
    )
    parser.add_argument("--gui", action="store_true", help="Launch the graphical interface (default when no args)")
    parser.add_argument("--status", action="store_true", help="Inspect binary status and print diagnostics")
    parser.add_argument("--patch", type=int, choices=list(range(2, 17)), metavar="N", help="Apply patch for N players (2=Pristine/Guest, 3-16=Tri-Gate)")
    parser.add_argument("--camera-only", action="store_true", help="Apply ONLY the cutscene camera fix (preserves original 2-player lobby; ideal for guest players)")
    parser.add_argument("--camera-fix", dest="camera_fix", action="store_true", default=None, help="Apply cinematic cutscene camera fix (for Host and Guests)")
    parser.add_argument("--no-camera-fix", dest="camera_fix", action="store_false", help="Disable cinematic cutscene camera fix")
    parser.add_argument("--restore", action="store_true", help="Restore binary to pristine original 2-player state")
    parser.add_argument("--force", action="store_true", help="Overwrite unrecognized modifications during restore or patch")
    parser.add_argument("--binary", type=Path, help="Explicit path to FC_m64.dll (auto-detects if omitted)")

    args = parser.parse_args()

    # Determine target binary
    target_dll = args.binary
    if not target_dll:
        installs = pe.detect_installations()
        if installs:
            target_dll = installs[0].dll_path
        else:
            print("Error: No Far Cry 5 installation auto-detected. Specify --binary <path/to/FC_m64.dll>")
            sys.exit(1)

    if args.status:
        info = pe.inspect_binary(target_dll)
        print(f"Target:       {target_dll}")
        print(f"Status:       {info['status']}")
        print(f"Message:      {info['message']}")
        print(f"SHA-256:      {info['sha256']}")
        print(f"Capacity:     {info['capacity']} players")
        cam_text = "Applied" if info.get('camera_fix_applied') else "Not Applied"
        print(f"Camera Fix:   {cam_text}")
        print(f"Game Running: {info['game_running']}")
        print(f"Backup Valid: {info['backup_valid']}")
        return

    if args.camera_only:
        print("\n[INFO] Mode: Guest / Camera Only")
        print("[INFO] Applying Cutscene Camera Fix ONLY — Original 2-player lobby capacity preserved.\n")
        ok = pe.apply_patch(
            target_dll,
            players=2,
            camera_fix=True,
            force=args.force,
        )
        sys.exit(0 if ok else 1)

    if args.patch is not None or args.camera_fix is not None:
        if args.camera_fix is False:
            print("\n[WARNING] Cutscene Camera Fix is DISABLED.")
            print("• Extra players (Players 3 and 4) will experience disrupted cutscenes (audio plays, but camera remains in 1st-person).")
            print("• Every participating player in your co-op session must install this patch locally to avoid cutscene camera bugs.\n")
        ok = pe.apply_patch(
            target_dll,
            players=args.patch,
            camera_fix=args.camera_fix,
            force=args.force,
        )
        sys.exit(0 if ok else 1)

    if args.restore:
        ok = pe.restore_original(target_dll, force=args.force)
        sys.exit(0 if ok else 1)

def main():
    if len(sys.argv) > 1 and not (len(sys.argv) == 2 and sys.argv[1] == "--gui"):
        run_cli()
    else:
        import gui_app
        gui_app.main()

if __name__ == "__main__":
    main()
