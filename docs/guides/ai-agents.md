# Use Limen from an AI agent

`limen mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server built into the CLI. It lets an AI agent ask what you can reach through Limen and why you can't reach something. It is **read-only**, runs on your machine, and uses your own login. Nothing new is granted.

This is spike 0 of [ADR-0032](../adr/0032-ai-agents-as-principals.md), which is still Proposed. There is no separate agent identity yet. The audit trail shows you, not the agent.

## Set it up

```sh
limen login
limen config mcp
```

`limen config mcp` prints the setup and changes no file. For Claude Code it is one command:

```sh
claude mcp add --scope user limen -- /path/to/limen mcp
```

`--scope user` makes it available in every project. Without it, Claude Code adds the server only to the directory you ran the command in.

Any client that reads an `mcpServers` block (a `.mcp.json`, for example) takes the JSON that the command prints. If you use a proxy other than the last one you logged in to, run `limen --proxy host:port config mcp` so the snippet carries it.

The snippet names the program by its full path, because desktop agents often start servers without your shell's `PATH`. The command prefers the `limen` found on your `PATH` when it is the same file, so a Homebrew install keeps a path that survives upgrades. If you move `limen`, run `limen config mcp` again and update the client.

Logins are short-lived. When yours expires, every tool answers `run limen login`. The agent cannot sign in for you, and that is deliberate.

## What the agent can do

| Tool | Runs | Answers |
|---|---|---|
| `limen_status` | `limen status --json` | Who you are, your roles, when the login expires |
| `limen_ls` | `limen ls --json` | The resources you may reach, optionally by text, type or labels |
| `limen_show` | `limen show --json` | One resource: type, labels, how you may access it |
| `limen_explain` | `limen explain --json` | Why you can or cannot reach a resource, and what would let you |
| `limen_requests` | `limen requests --json` | Your own access requests, optionally by status |

There is no tool that connects, requests, approves, locks or changes anything. To get access you run `limen request` yourself, and a person approves it in the console.

## What to know before you enable it

- **The agent sees what you see.** If you hold `limen:admin`, so does the agent's read access. Results (resource names, labels, request reasons) are sent to whichever model provider the agent uses.
- **Treat results as data.** A label or a reason is text someone typed. The server tells the model so, but that is advice, not a control.
- **Limits.** Each call is cut off after 30 seconds and its output after 256 KiB.
- **Not verified yet.** The tools have been tested against a fake runner and the real binary logged out, not against a live login. Report anything odd.

The design and its threats are in the [threat model](../threat-model.md) (TB15).
