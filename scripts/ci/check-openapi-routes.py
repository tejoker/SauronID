#!/usr/bin/env python3
"""Fail when the router and `schemas/openapi.yaml` have drifted apart.

The spec is what an integrator builds against, and nothing was checking that it
still described the server. Ninety-odd paths were kept in step by hand, which
works right up until the commit that adds a route and forgets the spec — and the
failure is silent in both directions: an undocumented route is invisible to
customers, and a documented route that no longer exists is worse, because
someone writes a client against it.

This reads the source rather than a running server on purpose. It needs no
database, no build, and no port, so it can run as an ordinary CI step.

Extraction is deliberately literal: `.route("<path>", ...)` inside a
`pub fn *_router()` body, and `.nest("<prefix>", <name>_router())` in the
top-level builder. Anything a regex cannot see — a route registered through a
variable, or a prefix computed at runtime — is invisible here too, so keep the
router literal. Axum 0.8 and OpenAPI 3.1 both spell parameters `{name}`, so no
translation is needed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORE_SRC = ROOT / "core" / "src"
SPEC = ROOT / "schemas" / "openapi.yaml"

ROUTE_RE = re.compile(r'\.route\(\s*"([^"]+)"')
NEST_RE = re.compile(r'\.nest\(\s*"([^"]+)"\s*,\s*([a-z_]+)\s*\(\s*\)')
ROUTER_FN_RE = re.compile(r"pub fn ([a-z_]+_router)\s*\(")

# Routes that exist but are deliberately absent from the public spec.
# Each entry needs a reason: this list is how a real gap gets excused, so an
# unexplained addition to it is the thing a reviewer should stop on.
UNDOCUMENTED_BY_DESIGN = {
    "/": "HTML landing page, not an API endpoint",
    "/dev/register_user": "dev-only, refused outside a development runtime",
    "/dev/buy_tokens": "dev-only, refused outside a development runtime",
    "/dev/leash/demo": "dev-only, refused outside a development runtime",
}


def strip_line_comments(text: str) -> str:
    # Only whole-line comments; a `//` inside a string literal must survive.
    return "\n".join(
        "" if line.lstrip().startswith("//") else line for line in text.splitlines()
    )


def strip_block_comments(text: str) -> str:
    # Must run AFTER line comments are gone. This codebase writes route globs
    # like `/agent/*` in prose, and `/*` there opens a block comment as far as
    # this regex is concerned — it silently ate ~90 lines of real router code,
    # including `/metrics` and `/readyz`, until the order was fixed.
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def strip_test_modules(text: str) -> str:
    """Drop `#[cfg(test)] mod ... { ... }` bodies.

    Test routers register throwaway paths (`/panic` for the catch-panic layer)
    that are not part of the API and must not be demanded of the spec.
    """
    out = []
    i = 0
    while True:
        m = re.compile(r"#\[cfg\(test\)\]\s*mod\s+\w+\s*\{").search(text, i)
        if not m:
            out.append(text[i:])
            return "".join(out)
        out.append(text[i : m.start()])
        depth, j = 1, m.end()
        while j < len(text) and depth:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            j += 1
        i = j


def clean(text: str) -> str:
    return strip_test_modules(strip_block_comments(strip_line_comments(text)))


def fn_body(text: str, start: int) -> str:
    """Source between the brace opening the function and its match."""
    open_at = text.index("{", start)
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at : i + 1]
    raise SystemExit(f"unbalanced braces from offset {start}")


def collect_routers(sources: dict[str, str]) -> dict[str, list[str]]:
    routers: dict[str, list[str]] = {}
    for text in sources.values():
        for m in ROUTER_FN_RE.finditer(text):
            body = fn_body(text, m.end())
            routers[m.group(1)] = ROUTE_RE.findall(body)
    return routers


def collect_paths(sources: dict[str, str], routers: dict[str, list[str]]) -> set[str]:
    main = sources["main.rs"]
    paths: set[str] = set(ROUTE_RE.findall(main))
    for prefix, router in NEST_RE.findall(main):
        if router not in routers:
            raise SystemExit(f"nested router {router}() has no definition")
        for route in routers[router]:
            # `.nest("/admin", ...)` + `.route("/stats")` -> `/admin/stats`.
            # A nested `.route("/")` is the prefix itself, not a trailing slash.
            joined = prefix.rstrip("/") + route
            paths.add(joined.rstrip("/") if joined != "/" else "/")
    return paths


def spec_paths() -> set[str]:
    """Top-level keys under `paths:` — parsed without pulling in PyYAML."""
    found: set[str] = set()
    in_paths = False
    for line in SPEC.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if re.match(r"^paths:\s*$", line):
            in_paths = True
            continue
        if in_paths:
            if re.match(r"^\S", line):  # a new top-level key ends the section
                in_paths = False
                continue
            m = re.match(r"^  (/\S*):\s*$", line)
            if m:
                found.add(m.group(1))
    return found


def main() -> int:
    sources = {
        p.name: clean(p.read_text(encoding="utf-8"))
        for p in (CORE_SRC / "main.rs", CORE_SRC / "routes.rs")
    }
    code = collect_paths(sources, collect_routers(sources))
    spec = spec_paths()

    if not code or not spec:
        print(f"extraction failed: {len(code)} routes, {len(spec)} spec paths")
        return 2

    missing = sorted(code - spec - set(UNDOCUMENTED_BY_DESIGN))
    stale = sorted(spec - code)

    for path in missing:
        print(f"NOT IN SPEC   {path}")
    for path in stale:
        print(f"NOT IN ROUTER {path}")

    if missing or stale:
        print(
            f"\n{len(missing)} undocumented route(s), {len(stale)} spec path(s) with no route.\n"
            "Update schemas/openapi.yaml, or add the route to UNDOCUMENTED_BY_DESIGN\n"
            f"in {Path(__file__).relative_to(ROOT)} with the reason it is not public."
        )
        return 1

    print(f"openapi.yaml matches the router: {len(code)} routes checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
