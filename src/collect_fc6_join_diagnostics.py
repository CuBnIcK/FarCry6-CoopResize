import argparse
import json
import math
from pathlib import Path

from fc6.build import TARGET_DLL, TARGET_EXE
from fc6.diagnostics import record_changes, sample_join_state, utc_now
from fc6.runtime import verify_module
from fc6.winproc import ReadOnlyProcess, find_module, select_process


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only FC6 join-state recorder, JSONL to stdout")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--duration", type=float, default=120)
    parser.add_argument("--interval", type=float, default=0.1)
    args = parser.parse_args()
    if not math.isfinite(args.duration) or not 0.1 <= args.duration <= 600:
        parser.error("--duration must be between 0.1 and 600 seconds")
    if not math.isfinite(args.interval) or not 0.05 <= args.interval <= 5:
        parser.error("--interval must be between 0.05 and 5 seconds")

    try:
        pid = select_process(TARGET_EXE, args.pid)
        base, size, path = find_module(pid, TARGET_DLL)
        with ReadOnlyProcess(pid) as process:
            variant = verify_module(process.read, base, size, Path(path))
            print(json.dumps({"event": "start", "utc": utc_now(), "pid": pid,
                              "variant": variant.name, "dll_sha256": variant.sha256, "read_only": True,
                              "duration_seconds": args.duration, "interval_seconds": args.interval}),
                  flush=True)
            for event in record_changes(lambda: sample_join_state(process.read, base),
                                        args.duration, args.interval):
                print(json.dumps(event), flush=True)
    except (OSError, RuntimeError) as error:
        # The class name helps tell a missing game from a hash mismatch without leaking addresses
        print(json.dumps({"event": "error", "utc": utc_now(), "error": "process_access_or_identity_failed",
                          "error_type": type(error).__name__}), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
