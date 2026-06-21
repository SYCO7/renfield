# Security Policy

## Reporting a vulnerability

Please report security issues **privately** via GitHub Security Advisories
(repo → **Security** → **Report a vulnerability**) rather than a public issue.
We aim to acknowledge within a few days.

## Trust model — read before running

Renfield is an offensive security tool. Run it **only** against agent stacks you
own or are explicitly authorized to test.

- **The MCP config you point at is trusted input.** `scan --live` / `verify` launch
  the server `command`/`args` from that config — exactly as the agent itself would.
  Do **not** run Renfield against a config you do not control.
- **The "sandbox" is an evidence workspace, not isolation.** It is a disposable temp
  directory with a canary secret and a localhost egress listener — it does **not**
  contain a hostile MCP server. To test **untrusted third-party** servers, run
  Renfield inside a throwaway **VM or container**.
- **Network:** the egress listener binds `127.0.0.1` on an ephemeral port only.
- **Secrets:** API keys are read from environment variables (`OPENAI_API_KEY`) or
  `--api-key`; they are never written to disk or printed.

## Hardening built in

- Every MCP request is **timeout-bounded** — a hung or hostile server is killed and
  the call fails rather than wedging the tool.
- Server-controlled text (tool output, tool names) is **stripped of terminal control
  characters** before printing, to prevent report spoofing via ANSI escapes.
- **Zero runtime dependencies** in the core (minimal supply-chain surface); the
  `openai` driver is an optional extra.
- CI runs with least-privilege `permissions: contents: read`.

## The bundled lab

`examples/vuln_server.py` is **intentionally insecure** (no path confinement, obeys
any instruction) — it is a test target. Keep it offline; never expose it on a network.
