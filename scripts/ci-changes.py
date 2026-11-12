#!/usr/bin/env python3
"""Decides which path-filtered workflows a pull request would have started.

    scripts/ci-changes.py FILE_LIST WORKFLOW...      # FILE_LIST: one changed path per line ("-" = stdin)
    scripts/ci-changes.py --self-test

Prints `<workflow>=true|false` per workflow (the format of $GITHUB_OUTPUT). The patterns are read
from the first `paths:` list in `.github/workflows/<workflow>.yml` (its `push` trigger), so the
filter lives in one place. Matching follows GitHub's rules: `*` stops at `/`, `**` does not, a
`!` pattern excludes, and the last pattern that matches a file decides.
Used by .github/workflows/ci.yml. Standard library only.
"""
import re
import sys
from pathlib import Path


def read_patterns(text):
    patterns, seen = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if not seen:
            seen = stripped.startswith("paths:")
            continue
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r'^-\s+"(.*)"\s*(#.*)?$', stripped) or re.match(r"^-\s+'(.*)'\s*(#.*)?$", stripped)
        if not m:
            break
        patterns.append(m.group(1))
    if not patterns:
        raise SystemExit("no `paths:` list found")
    return patterns


def to_regex(glob):
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def triggers(patterns, files):
    compiled = [(p.startswith("!"), to_regex(p.lstrip("!"))) for p in patterns]
    for f in files:
        included = False
        for negated, rx in compiled:
            if rx.match(f):
                included = not negated
        if included:
            return True
    return False


def self_test():
    p = ["**", "!docs/**", "!**.md", "!.github/**", ".github/workflows/rust.yml", "docs/cli-reference.md"]
    cases = [
        (["crates/a/src/lib.rs"], True),
        (["docs/guide.md"], False),
        (["README.md"], False),
        (["crates/a/README.md"], False),
        ([".github/workflows/ci.yml"], False),
        ([".github/workflows/rust.yml"], True),
        (["docs/cli-reference.md"], True),
        (["docs/a.md", "crates/x.rs"], True),
        (["Cargo.toml"], True),
    ]
    for files, want in cases:
        assert triggers(p, files) == want, (files, want)
    q = ["Cargo.toml", "**/Cargo.toml", "deny.toml"]
    assert triggers(q, ["crates/a/Cargo.toml"]) and triggers(q, ["Cargo.toml"])
    assert not triggers(q, ["crates/a/src/Cargo.lock"])
    print("self-test ok")


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) < 3:
        raise SystemExit(__doc__)
    src = sys.stdin if argv[1] == "-" else open(argv[1])
    files = [line.strip() for line in src if line.strip()]
    root = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    for name in argv[2:]:
        patterns = read_patterns((root / f"{name}.yml").read_text())
        print(f"{name}={'true' if triggers(patterns, files) else 'false'}")


if __name__ == "__main__":
    main(sys.argv)
