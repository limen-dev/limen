#!/usr/bin/env python3
"""Generate everything that lists the dev users from dev-users.toml.

    python3 deploy/compose/gen-dev-users.py          # rewrite the generated parts
    python3 deploy/compose/gen-dev-users.py --check  # fail if they are stale (CI)
"""
import pathlib
import re
import sys
import tomllib
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
data = tomllib.loads((HERE / "dev-users.toml").read_text())
users = data["user"]

# Which roles do the example policy's mappings give each group?
mappings = (ROOT / "examples/policy/mappings.yaml").read_text()
roles_for = {}
for group, roles in re.findall(r"idp_group:\s*([\w:-]+)\s*,\s*roles:\s*\[(.*?)\]", mappings):
    roles_for[group] = [r.strip().strip('"') for r in roles.split(",") if r.strip()]


def roles_of(user):
    out = []
    for g in user["groups"]:
        for r in roles_for.get(g, []):
            if r not in out:
                out.append(r)
    return out


def replace_block(path, begin, end, body):
    text = path.read_text()
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.S)
    if not pattern.search(text):
        sys.exit(f"{path}: missing the markers {begin!r} ... {end!r}")
    return pattern.sub(lambda _: f"{begin}\n{body}\n{end}", text)


outputs = {}

# Dex
dex = "\n".join(
    f"""  - email: {u['email']}
    hash: "{data['password_hash']}"
    username: {u['id']}
    userID: {u['user_id']}
    groups: [{', '.join(u['groups'])}]"""
    for u in users
)
dex_path = HERE / "dex/config.yaml"
outputs[dex_path] = replace_block(dex_path, "  # BEGIN dev-users (generated from ../dev-users.toml)", "  # END dev-users", dex)

# README table
rows = ["| User | Groups | Roles with `examples/policy` |", "|---|---|---|"]
for u in users:
    roles = roles_of(u)
    rows.append(
        f"| `{u['email']}` | {', '.join('`' + g + '`' for g in u['groups'])} | "
        + (", ".join(f"`{r}`" for r in roles) if roles else "none, so login is denied")
        + " |"
    )
readme_path = HERE / "README.md"
outputs[readme_path] = replace_block(readme_path, "<!-- BEGIN dev-users (generated from dev-users.toml) -->", "<!-- END dev-users -->", "\n".join(rows))

# Shell variables for the demo scripts
sh = ["# Generated from dev-users.toml by gen-dev-users.py. Do not edit.", f'DEV_PASSWORD="password"']
for u in users:
    name = u["id"].upper()
    sh.append(f'{name}="{u["email"]}"')
    sh.append(f'{name}_ENC="{urllib.parse.quote(u["email"], safe="")}"')
outputs[HERE / "dev-users.sh"] = "\n".join(sh) + "\n"

stale = [str(p.relative_to(ROOT)) for p, text in outputs.items() if not p.exists() or p.read_text() != text]
if "--check" in sys.argv:
    if stale:
        sys.exit("stale, run gen-dev-users.py: " + ", ".join(stale))
    print("dev users are up to date")
else:
    for p, text in outputs.items():
        p.write_text(text)
    print("generated:", ", ".join(str(p.relative_to(ROOT)) for p in outputs))
