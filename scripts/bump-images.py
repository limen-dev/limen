#!/usr/bin/env python3
"""Finds newer container image tags for deploy/compose/.env and, with --apply, bumps them.

    scripts/bump-images.py            # report only
    scripts/bump-images.py --apply    # edit the files, then run scripts/check-versions.sh

Rules (issue #94):
- A tag is compared with others of the same shape: its digit runs replaced by '#', so
  `18-alpine` follows `19-alpine`-shaped tags and `v1.35.4-k3s1` follows `v1.35.5-k3s1`, never
  `18` or `18-trixie`. Release candidates and other suffixes therefore never match.
- A newer tag with the same first number is a bump (patch/minor) when the tag has three or more
  numbers (`2.46.0`, `1.99.0-trixie`). Tags with one or two (`18-alpine`, `4.0`, `3.22`) are
  release lines that already follow patch releases, so a newer one is a new line, not a bump:
  reported, never applied, like a greater first number ("major").
- Digest-pinned images (`name@sha256:...`) are reported and never bumped.
- Variables in SKIP are left alone, with the reason printed.

Besides .env it keeps in step the places that cannot read it (the CI service containers in
.github/workflows/rust.yml, rust-toolchain.toml and mise.toml), as scripts/check-versions.sh
requires. Standard library only; it reads public registries anonymously.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / "deploy/compose/.env"

# Variables that are not followed, with the reason.
SKIP = {
    "MONGO_IMAGE": "held at 8.2: 8.0 and 8.3 refuse to start on Linux 6.19+ (SERVER-121912)",
    "SSHD_BASE_IMAGE": "tracked by hand next to ALPINE_IMAGE (see the comment in .env)",
    "DISTROLESS_IMAGE": "moving tag without a version",
}
# Release counters with no major: every newer tag is a bump.
FLAT = {"TRINO_IMAGE"}

NUM = re.compile(r"\d+")


def shape(tag):
    return NUM.sub("#", tag)


def numbers(tag):
    return tuple(int(n) for n in NUM.findall(tag))


def split_ref(ref):
    """`host/name:tag` -> (host, repository, tag). Docker Hub is the default host."""
    name, _, tag = ref.rpartition(":")
    parts = name.split("/")
    if "." in parts[0] or ":" in parts[0]:
        host, repo = parts[0], "/".join(parts[1:])
    else:
        host, repo = "registry-1.docker.io", name if "/" in name else f"library/{name}"
    return host, repo, tag


def get(url, token=None):
    req = urllib.request.Request(url, headers={"User-Agent": "limen-bump-images"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    return urllib.request.urlopen(req, timeout=30)


def bearer_token(challenge):
    fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    url = f"{fields['realm']}?service={fields.get('service', '')}&scope={fields.get('scope', '')}"
    with get(url) as resp:
        body = json.load(resp)
    return body.get("token") or body["access_token"]


def list_tags(host, repo):
    url = f"https://{host}/v2/{repo}/tags/list?n=1000"
    token, tags = None, []
    while url:
        try:
            resp = get(url, token)
        except urllib.error.HTTPError as err:
            if err.code != 401 or token:
                raise
            repo_scope = f'repository:{repo}:pull'
            challenge = err.headers.get("Www-Authenticate", "")
            if "scope=" not in challenge:
                challenge += f',scope="{repo_scope}"'
            token = bearer_token(challenge)
            continue
        with resp:
            tags += json.load(resp).get("tags") or []
            link = resp.headers.get("Link", "")
        match = re.search(r"<([^>]+)>;\s*rel=\"next\"", link)
        url = None
        if match:
            nxt = match.group(1)
            url = nxt if nxt.startswith("http") else f"https://{host}{nxt}"
    return tags


def newest(current, tags, flat):
    """(best bump, best major) among tags of the same shape as `current`."""
    want, cur = shape(current), numbers(current)
    same = [t for t in tags if shape(t) == want and numbers(t) > cur]
    patchable = flat or len(cur) >= 3
    bump = [t for t in same if patchable and (flat or numbers(t)[0] == cur[0])]
    major = [t for t in same if not flat and not (patchable and numbers(t)[0] == cur[0])]
    key = numbers
    return (max(bump, key=key) if bump else None, max(major, key=key) if major else None)


def read_images():
    out = []
    for line in ENV.read_text().splitlines():
        m = re.match(r"^([A-Z_]+_IMAGE)=(\S+)$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def replace_in(path, old, new):
    text = path.read_text()
    if old not in text:
        return False
    path.write_text(text.replace(old, new))
    return True


def apply_bump(var, old_ref, new_ref):
    replace_in(ENV, f"{var}={old_ref}", f"{var}={new_ref}")
    ci = ROOT / ".github/workflows/rust.yml"
    if var in ("POSTGRES_IMAGE", "JAEGER_IMAGE"):
        replace_in(ci, f"image: {old_ref}\n", f"image: {new_ref}\n")
    if var == "RUST_IMAGE":
        old_v = old_ref.split(":")[1].split("-")[0]
        new_v = new_ref.split(":")[1].split("-")[0]
        replace_in(ROOT / "rust-toolchain.toml", f'channel = "{old_v}"', f'channel = "{new_v}"')
        replace_in(ROOT / "mise.toml", f'rust = {{ version = "{old_v}"', f'rust = {{ version = "{new_v}"')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="edit the files (bumps only, never majors)")
    args = ap.parse_args()

    bumps, majors, notes, errors = [], [], [], []
    for var, ref in read_images():
        if var in SKIP:
            notes.append(f"{var}: not followed, {SKIP[var]}")
            continue
        if "@sha256:" in ref:
            notes.append(f"{var}: pinned by digest ({ref.split('@')[0]}), bump by hand")
            continue
        host, repo, tag = split_ref(ref)
        if not NUM.search(tag):
            notes.append(f"{var}: tag `{tag}` has no version, not followed")
            continue
        try:
            tags = list_tags(host, repo)
        except (urllib.error.URLError, OSError, KeyError, ValueError) as err:
            errors.append(f"{var}: could not list tags of {host}/{repo}: {err}")
            continue
        bump, major = newest(tag, tags, var in FLAT)
        prefix = ref[: -len(tag)]
        if bump:
            bumps.append((var, ref, prefix + bump))
        if major:
            majors.append((var, ref, prefix + major))

    print("## Image updates\n")
    if bumps:
        print("Bumped (same major):\n")
        for var, old, new in bumps:
            print(f"- `{var}`: `{old}` -> `{new}`")
    else:
        print("No patch or minor updates.")
    if majors:
        print("\nNew major versions or release lines, not applied (decide by hand):\n")
        for var, old, new in majors:
            print(f"- `{var}`: `{old}` -> `{new}`")
    if notes:
        print("\nNot followed:\n")
        for n in notes:
            print(f"- {n}")
    if errors:
        print("\nErrors:\n")
        for e in errors:
            print(f"- {e}")

    if args.apply:
        for var, old, new in bumps:
            apply_bump(var, old, new)
    # An unreachable registry must fail the run, not look like "nothing to update".
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
