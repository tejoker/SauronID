#!/usr/bin/env python3
"""Prove every state-changing release job depends on independent-signoff.

The named floor below is not the whole check: any job carrying a publish command
is held to the same rule, so moving or adding one cannot quietly open a path
around the assessment.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else None
    if path is None or not path.is_file():
        raise SystemExit("usage: verify-release-dag.py <release-workflow.yml>")

    jobs: dict[str, set[str]] = {}
    bodies: dict[str, list[str]] = {}
    current: str | None = None
    in_jobs = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        match = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            jobs[current] = set()
            bodies[current] = []
            continue
        if current is None:
            continue
        bodies[current].append(line)
        match = re.match(r"^    needs:\s*(.+?)\s*$", line)
        if not match:
            continue
        raw = match.group(1)
        if raw.startswith("[") and raw.endswith("]"):
            deps = [item.strip() for item in raw[1:-1].split(",")]
        else:
            deps = [raw.strip()]
        jobs[current].update(dep for dep in deps if dep)

    # A floor: these jobs must exist. `npm` (@sauronid/agentic) and the sdist
    # half of `pypi` deliberately left this workflow for publish-clients.yml —
    # they are Apache-2.0 clients that hold no keys and enforce nothing, and
    # keeping them here made the un-gated lane unusable, because
    # `@sauronid/mcp-server` depends on `@sauronid/agentic`. The platform wheels
    # stayed, as `pypi-wheels`, because each bundles the `agent-action-tool`
    # workstation binary.
    required = {
        "tool-binaries",
        "wheels",
        "npm-tool",
        "images",
        "pypi-wheels",
        "github-release",
    }
    missing = required - jobs.keys()
    if missing:
        raise SystemExit(f"release workflow is missing jobs: {sorted(missing)}")

    # The list above is a floor, not the check. Editing this file to move a job
    # out was exactly how the allowlist got stale, so anything that LOOKS like it
    # publishes is held to the same rule whether or not it is named above.
    PUBLISH_MARKERS = (
        "npm publish",
        "gh-action-pypi-publish",
        "docker/build-push-action",
        "docker push",
        "gh release create",
        "softprops/action-gh-release",
        "cosign sign",
    )
    publishers = {
        job
        for job, body in bodies.items()
        if any(marker in "\n".join(body) for marker in PUBLISH_MARKERS)
    }
    required |= publishers

    def descends_from_signoff(job: str, seen: set[str] | None = None) -> bool:
        if job == "independent-signoff":
            return True
        seen = set() if seen is None else seen
        if job in seen:
            raise SystemExit(f"release dependency cycle at {job}")
        seen.add(job)
        return any(descends_from_signoff(dep, seen.copy()) for dep in jobs.get(job, set()))

    bypasses = sorted(job for job in required if not descends_from_signoff(job))
    if bypasses:
        raise SystemExit(f"publishing jobs bypass independent-signoff: {bypasses}")
    print("release publication DAG is sign-off bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
