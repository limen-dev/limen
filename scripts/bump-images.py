#!/usr/bin/env python3
"""Finds newer container image tags for deploy/compose/.env and optionally applies them.

    scripts/bump-images.py            # report only
    scripts/bump-images.py --apply    # edit .env and the places that must agree, then run check-versions.sh

Rules (see #94):
- A tag is followed within its own stream: same prefix and suffix around the numbers
  (`18-alpine` stays `N-alpine`, `v2.46.0` stays `vN.N.N`), same number of numeric parts. The stream is the
  first two numbers of a tag with three or more (patch bumps only), and all of them otherwise.
- A newer stream (minor or major) is only reported, never applied.
- Digest-pinned images (`name@sha256:...`) are reported, never changed.
- `--apply` also updates the places that cannot read .env: the CI service image for POSTGRES_IMAGE, and
  rust-toolchain.toml and mise.toml for RUST_IMAGE. Then scripts/check-versions.sh must pass.

Registries: Docker Hub, ghcr.io, docker.elastic.co, gcr.io (anonymous pull tokens). Needs network.
"""
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / "deploy/compose/.env"
CI = ROOT / ".github/workflows/ci.yml"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
MISE = ROOT / "mise.toml"

# Variables whose value is not a plain image reference, or that follow another file.
SKIP = {"GRAFANA_TRINO_PLUGIN"}
# Tags that look like versions but are not releases.
PRERELEASE = re.compile(r"(rc|alpha|beta|snapshot|nightly|preview|dev)", re.I)
NUM = re.compile(r"\d+")


def split_ref(ref):
    """registry, repository, tag-or-None, digest-or-None"""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", "/".join(parts)
        if "/" not in repo:
            repo = "library/" + repo
    return registry, repo, tag, digest


def get_json(url, token=None):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def list_tags(registry, repo):
    host = {"docker.io": "registry-1.docker.io"}.get(registry, registry)
    token = None
    try:
        if registry == "docker.io":
            q = urllib.parse.urlencode({"service": "registry.docker.io", "scope": f"repository:{repo}:pull"})
            token = get_json("https://auth.docker.io/token?" + q)["token"]
        elif registry == "ghcr.io":
            token = get_json(f"https://ghcr.io/token?scope=repository:{repo}:pull")["token"]
        tags, url = [], f"https://{host}/v2/{repo}/tags/list?n=1000"
        while url:
            req = urllib.request.Request(url)
            if token:
                req.add_header("Authorization", "Bearer " + token)
            with urllib.request.urlopen(req, timeout=30) as r:
                tags += json.load(r).get("tags") or []
                link = r.headers.get("Link", "")
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = (f"https://{host}{m.group(1)}" if m.group(1).startswith("/") else m.group(1)) if m else None
        return tags
    except Exception as e:  # network or auth: report, do not guess
        print(f"warn: cannot list tags for {registry}/{repo}: {e}", file=sys.stderr)
        return None


def shape(tag):
    """(template with numbers replaced by #, numbers) or None when the tag has no number."""
    nums = [int(n) for n in NUM.findall(tag)]
    return (NUM.sub("#", tag), nums) if nums else None


def candidates(current, tags):
    """Returns (newest patch-level tag in the same stream, newest tag of a newer stream).

    The stream is the first two numbers when a tag has three or more (`v2.46.0` is stream 2.46), and all of
    them otherwise (`8.4`, `18-alpine`, `483` are streams already): those can only be reported.
    """
    cur = shape(current)
    if cur is None:
        return None, None
    tmpl, nums = cur
    keep = 2 if len(nums) >= 3 else len(nums)
    same, newer = [], []
    for t in tags:
        if PRERELEASE.search(t):
            continue
        s = shape(t)
        if s is None or s[0] != tmpl or len(s[1]) != len(nums):
            continue
        if s[1][:keep] == nums[:keep]:
            if s[1] > nums:
                same.append((s[1], t))
        elif s[1][:keep] > nums[:keep]:
            newer.append((s[1], t))
    return (max(same)[1] if same else None), (max(newer)[1] if newer else None)


def main():
    apply = "--apply" in sys.argv
    lines = ENV.read_text().splitlines()
    changes = {}  # var -> (old ref, new ref)
    for line in lines:
        m = re.match(r"^([A-Z0-9_]+_IMAGE)=(\S+)$", line)
        if not m or m.group(1) in SKIP:
            continue
        var, ref = m.groups()
        registry, repo, tag, digest = split_ref(ref)
        if digest:
            print(f"pinned   {var}: {ref} (digest-pinned, bump by hand)")
            continue
        if tag is None:
            print(f"skip     {var}: {ref} (no tag)")
            continue
        tags = list_tags(registry, repo)
        if tags is None:
            continue
        best, other = candidates(tag, tags)
        prefix = ref[: -len(tag)]
        if best:
            changes[var] = (ref, prefix + best)
            print(f"bump     {var}: {ref} -> {prefix + best}")
        else:
            print(f"current  {var}: {ref}")
        if other:
            print(f"newer    {var}: {prefix + other} (new stream, not applied; needs a human)")

    if not apply or not changes:
        if apply:
            print("nothing to apply")
        return 0

    text = ENV.read_text()
    ci = CI.read_text()
    for var, (old, new) in changes.items():
        text = text.replace(f"{var}={old}\n", f"{var}={new}\n")
        if var == "POSTGRES_IMAGE":
            ci = ci.replace(f"image: {old}\n", f"image: {new}\n")
        if var == "RUST_IMAGE":
            ov, nv = old.split(":")[1].split("-")[0], new.split(":")[1].split("-")[0]
            for f, pat in ((TOOLCHAIN, f'channel = "{ov}"'), (MISE, f'rust = {{ version = "{ov}"')):
                f.write_text(f.read_text().replace(pat, pat.replace(ov, nv), 1))
    ENV.write_text(text)
    CI.write_text(ci)
    subprocess.run([str(ROOT / "scripts/check-versions.sh")], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
