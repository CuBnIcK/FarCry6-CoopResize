import argparse
import json
import sys
from pathlib import Path

from fc6.build import BUILDS
from fc6.variants import ORIGINAL, RECOMMENDED, VARIANTS, create_package


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a hash-verified experimental FC6 DLL and a pristine backup, without installing"
    )
    parser.add_argument("source", type=Path, nargs="?", help="Unmodified FC_m64d3d12.dll, Steam or Ubisoft Connect")
    parser.add_argument("--output-dir", type=Path, help="New or empty directory for the package")
    parser.add_argument("--variant", choices=[name for name in VARIANTS if name != ORIGINAL.name],
                        default=RECOMMENDED)
    parser.add_argument("--list", action="store_true", help="List variants and exit")
    args = parser.parse_args()
    if args.list:
        for variant in VARIANTS.values():
            marker = " (default)" if variant.name == RECOMMENDED else ""
            print(f"{variant.name}{marker}\n  {variant.summary}")
            for build in BUILDS.values():
                if digest := variant.hash_for(build):
                    print(f"  {build.name} sha256 {digest}")
        return 0
    if args.source is None or args.output_dir is None:
        parser.error("source and --output-dir are required")
    try:
        print(json.dumps(create_package(args.source, args.output_dir, args.variant), indent=2))
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
