"""Write (or check) the shipped lockfiles of the AgentDojo suites.

    python bench/agentdojo/build_locks.py            # regenerate suites/<suite>/agentguard.lock
    python bench/agentdojo/build_locks.py --check    # fail if a shipped lockfile is out of date

The lockfile is generated from the installed AgentDojo suite and the declarations in
suites/<suite>/declarations.yaml. If AgentDojo changes a tool, --check fails and the lock must be
reviewed again, which is exactly what the lockfile is for.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import SUITE_DIR, SUITES, agentdojo_version, load_suite, shipped_lock_text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    check = parser.parse_args().check
    stale: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        for name in SUITES:
            generated = shipped_lock_text(load_suite(name), name, Path(tmp))
            target = SUITE_DIR / name / "agentguard.lock"
            if check:
                if not target.exists() or target.read_text(encoding="utf-8") != generated:
                    stale.append(name)
            else:
                target.write_text(generated, encoding="utf-8")
                print(f"wrote {target}")
    if stale:
        print(f"out of date for agentdojo {agentdojo_version()}: {', '.join(stale)}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
