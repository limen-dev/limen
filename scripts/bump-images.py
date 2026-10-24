#!/usr/bin/env python3
"""Finds newer tags for the container images in deploy/compose/.env (issue #94).

    scripts/bump-images.py            report what is newer; change nothing
    scripts/bump-images.py --apply    edit .env and the places that must agree, then
                                      run scripts/check-versions.sh

Dependabot cannot do this: compose `image:` values are ${VAR} references. Policy (held
variables) is in deploy/compose/image-updates.toml. Standard library only.
"""
import argparse
import json
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / "deploy/compose/.env"
POLICY = ROOT / "deploy/compose/image-updates.toml"
# Where an image string is written out because the place cannot read .env.
CI_YML = ROOT / ".github/workflows/ci-rust.yml"
CI_VARS = {"POSTGRES_IMAGE", "KMS_IMAGE"}


def parse_env(text):
    """Returns {VAR: value} for the *_IMAGE lines."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Z0-9_]+_IMAGE)=(\S+)$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def split_ref(ref):
    """'ghcr.io/dexidp/dex:v1.2.3' -> ('ghcr.io', 'dexidp/dex', 'v1.2.3'); None for a digest."""
    if "@" in ref:
        return None
    name, _, tag = ref.rpartition(":")
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, rest
    else:
        registry, repo = "registry-1.docker.io", name if "/" in name else f"library/{name}"
    return registry, repo, tag


def tag_shape(tag):
    """Regex matching tags of the same stream, and the numbers of `tag`; None if it has none."""
    parts = re.split(r"(\d+)", tag)
    if len(parts) < 3:
        return None
    pattern = "".join(r"(\d+)" if i % 2 else re.escape(p) for i, p in enumerate(parts))
    return re.compile(f"^{pattern}$"), tuple(int(n) for n in parts[1::2])


def newest(tag, candidates):
    """Returns (bump, major): the newest tag with the same first number, and the newest overall."""
    shape = tag_shape(tag)
    if shape is None:
        return None, None
    rx, cur = shape
    found = []
    for c in candidates:
        m = rx.match(c)
        if m:
            found.append((tuple(int(n) for n in m.groups()), c))
    found.sort()
    bump = max((f for f in found if f[0][0] == cur[0] and f[0] > cur), default=None)
    major = max((f for f in found if f[0][0] > cur[0]), default=None)
    return bump and bump[1], major and major[1]


def http_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r), r.headers.get("Link", "")


def list_tags(registry, repo):
    """Lists tags through the registry v2 API with an anonymous token when one is asked for."""
    url = f"https://{registry}/v2/{repo}/tags/list?n=1000"
    headers = {}
    tags = []
    while url:
        try:
            data, link = http_json(url, headers)
        except urllib.error.HTTPError as e:
            challenge = e.headers.get("WWW-Authenticate", "")
            if e.code != 401 or "Bearer" not in challenge or "Authorization" in headers:
                raise
            kv = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
            q = urllib.parse.urlencode({"service": kv.get("service", ""), "scope": f"repository:{repo}:pull"})
            token, _ = http_json(f"{kv['realm']}?{q}")
            headers = {"Authorization": "Bearer " + (token.get("token") or token["access_token"])}
            continue
        tags += data.get("tags") or []
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = urllib.parse.urljoin(url, m.group(1)) if m else None
    return tags


def apply_bump(var, old, new, env_text):
    """Rewrites .env and the files that cannot read it. Returns the new .env text."""
    env_text = env_text.replace(f"{var}={old}", f"{var}={new}")
    if var in CI_VARS:
        CI_YML.write_text(CI_YML.read_text().replace(old, new))
    if var == "RUST_IMAGE":
        ver = new.removeprefix("rust:").split("-")[0]
        for path, rx in ((ROOT / "rust-toolchain.toml", r'^(channel\s*=\s*)"[^"]+"'),
                         (ROOT / "mise.toml", r'^(rust\s*=\s*\{\s*version\s*=\s*)"[^"]+"')):
            path.write_text(re.sub(rx, rf'\g<1>"{ver}"', path.read_text(), flags=re.M))
    return env_text


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="edit the files instead of only reporting")
    ap.add_argument("--summary", metavar="FILE", help="write a Markdown summary (a PR body) to FILE")
    args = ap.parse_args()

    env_text = ENV.read_text()
    hold = tomllib.loads(POLICY.read_text()).get("hold", {})
    rows, bumped = [], 0
    for var, ref in parse_env(env_text).items():
        if var in hold:
            rows.append((var, ref, "held", hold[var]))
            continue
        parts = split_ref(ref)
        if parts is None:
            rows.append((var, ref, "digest", "pinned by digest; update by hand"))
            continue
        registry, repo, tag = parts
        if tag_shape(tag) is None:
            rows.append((var, ref, "moving", "tag has no version to compare"))
            continue
        try:
            bump, major = newest(tag, list_tags(registry, repo))
        except (urllib.error.URLError, KeyError, ValueError) as e:
            rows.append((var, ref, "error", str(e)))
            continue
        new_ref = ref.removesuffix(tag) + bump if bump else None
        if new_ref:
            bumped += 1
            if args.apply:
                env_text = apply_bump(var, ref, new_ref, env_text)
            rows.append((var, ref, "bump", new_ref))
        if major:
            rows.append((var, ref, "major", f"{ref.removesuffix(tag)}{major} (not bumped)"))
        if not bump and not major:
            rows.append((var, ref, "current", ""))

    for var, ref, kind, note in rows:
        print(f"{kind:8} {var:22} {ref}  {note}")
    if args.apply:
        ENV.write_text(env_text)
    if args.summary:
        lines = ["Automated image bumps (`scripts/bump-images.py`, #94). CI runs when this is marked ready.", ""]
        for title, kinds in (("Bumped", {"bump"}), ("Newer major, not bumped", {"major"}),
                             ("Needs a human", {"digest", "error"})):
            hit = [r for r in rows if r[2] in kinds]
            if hit:
                lines += [f"**{title}**", *[f"- `{v}`: `{ref}` -> {note}" if k == "bump" else f"- `{v}`: {note}" for v, ref, k, note in hit], ""]
        Path(args.summary).write_text("\n".join(lines))
    if args.apply and bumped:
        subprocess.run([str(ROOT / "scripts/check-versions.sh")], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
