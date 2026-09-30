"""Download Semgrep's p/default rule pack for offline scanning.

Run once while online: `.venv/bin/python fetch_rules.py`. The pack is covered by
the Semgrep Rules License, so it is saved locally (gitignored) rather than
redistributed with this project.
"""

import sys
import urllib.request
from pathlib import Path

URL = "https://semgrep.dev/c/p/default"
DEST = Path(__file__).parent / "rules" / "p-default.yml"


def main() -> int:
    request = urllib.request.Request(URL, headers={"User-Agent": "smart-security-pipeline"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read()
    except OSError as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        return 1
    if not body.startswith(b"rules:"):
        print("Unexpected response; rule pack not saved.", file=sys.stderr)
        return 1
    tmp = DEST.with_suffix(".tmp")
    tmp.write_bytes(body)
    tmp.replace(DEST)
    print(f"Saved {body.count(b'- id:')} rules to {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
