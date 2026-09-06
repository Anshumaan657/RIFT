"""Create a deterministic runtime copy of the immutable lab seed."""

import argparse
import hashlib
import json
from pathlib import Path

SOURCE = Path(__file__).parents[1] / "fixtures" / "seed.json"


def canonical_seed() -> bytes:
    parsed = json.loads(SOURCE.read_text(encoding="utf-8"))
    return (json.dumps(parsed, indent=2, sort_keys=True) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/tmp/rift-lab-seed.json"))
    args = parser.parse_args()
    payload = canonical_seed()
    args.output.write_bytes(payload)
    print(f"seed_path={args.output} sha256={hashlib.sha256(payload).hexdigest()}")


if __name__ == "__main__":
    main()
