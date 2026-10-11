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
        description="Far Cry 5 Campaign Co-op Host Patcher (Tri-Gate Architecture)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  FC5CampaignCoopPatcher.exe
  FC5CampaignCoopPatcher.exe --status
  FC5CampaignCoopPatcher.exe --patch 3
  FC5CampaignCoopPatcher.exe --patch 4
  FC5CampaignCoopPatcher.exe --restore
        """,
    )
    parser.add_argument("--gui", action="store_true", help="Launch the graphical interface (default when no args)")
    parser.add_argument("--status", action="store_true", help="Inspect binary status and print diagnostics")
    parser.add_argument("--patch", type=int, choices=list(range(3, 17)), metavar="N", help="Apply Tri-Gate patch for N players (3-16)")
    parser.add_argument("--restore", action="store_true", help="Restore binary to pristine original 2-player state")
    parser.add_argument("--force", action="store_true", help="Overwrite unrecognized modifications during restore")
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
        print(f"Game Running: {info['game_running']}")
        print(f"Backup Valid: {info['backup_valid']}")
        return

    if args.patch:
        ok = pe.apply_patch(target_dll, players=args.patch, force=args.force)
        sys.exit(0 if ok else 1)

    if args.restore:
        ok = pe.restore_original(target_dll, force=args.force)
        sys.exit(0 if ok else 1)

def main():
    # If launched with arguments other than just the executable name, check if GUI is requested or CLI
    if len(sys.argv) > 1 and not (len(sys.argv) == 2 and sys.argv[1] == "--gui"):
        run_cli()
    else:
        import gui_app
        gui_app.main()

if __name__ == "__main__":
    main()
