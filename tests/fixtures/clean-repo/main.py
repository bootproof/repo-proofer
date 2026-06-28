#!/usr/bin/env python3
"""clean-repo main entrypoint.

A deliberately boring, well-behaved demo. Reads a local file, prints
output, writes a result file to /tmp, exits 0. No network, no secrets,
no surprises. repo-proofer should report BOOTS: YES with zero warnings.
"""

import json
import os
import sys
import tempfile
from pathlib import Path


def main() -> int:
    print("Hello from clean-repo!")
    print("This repo runs entirely offline and exits cleanly.")

    # Read a local file (the repo's own README) — strace will see this.
    readme = Path(__file__).parent / "README.md"
    if readme.exists():
        first_line = readme.read_text().splitlines()[0]
        print(f"README title: {first_line}")

    # Write a result file to /tmp (writable via --tmpfs /tmp).
    result = {"status": "ok", "pid": os.getpid()}
    out_path = Path(tempfile.gettempdir()) / "clean-repo-result.json"
    out_path.write_text(json.dumps(result))
    print(f"Wrote result to {out_path}")

    print("Done. Exiting 0.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
