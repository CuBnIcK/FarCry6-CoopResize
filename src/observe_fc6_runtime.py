import argparse
import json
import sys
from pathlib import Path

from fc6.build import TARGET_DLL, TARGET_EXE
from fc6.runtime import sample_sessions, verify_module
from fc6.winproc import ReadOnlyProcess, find_module, select_process


def observe_process(pid: int | None) -> dict:
    pid = select_process(TARGET_EXE, pid)
    base, size, module_path = find_module(pid, TARGET_DLL)
    with ReadOnlyProcess(pid) as process:
        variant = verify_module(process.read, base, size, Path(module_path))
        return {"pid": pid, "variant": variant.name, "dll_sha256": variant.sha256,
                **sample_sessions(process.read, base)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only FC6 session-capacity probe, not a co-op unlock patch"
    )
    parser.add_argument("--pid", type=int, help="Select an already running FarCry6.exe")
    args = parser.parse_args()
    try:
        print(json.dumps(observe_process(args.pid), indent=2))
    except (OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
