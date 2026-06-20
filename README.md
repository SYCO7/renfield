# toxitrace

**Penetration testing for AI agent / MCP infrastructure.**

`toxitrace` points at an AI agent's own MCP tool mesh, finds the
`untrusted-source → sensitive-read → external-sink` chains that let attacker
content steer the agent into stealing and leaking data **across server
boundaries** (the cross-server *confused-deputy* / *lethal-trifecta* class), and
— in later versions — **proves** each chain by planting a payload and observing a
real side effect (file read, network egress, token reuse). Local-first, no
telemetry.

## Why this exists

Prior art splits into buckets that never meet:

| Tool | Does | Misses |
|------|------|--------|
| mcp-scan / SkillSpector | flags one tool's description | no cross-server, no execution |
| MCPhound | maps cross-server paths | **never executes** |
| Snyk Toxic Flow Analysis | models flow graph + score | no execution |
| VIPER-MCP | runs + proves by side effect | **single-server only**, no confused-deputy/OAuth |
| promptfoo / AgentDojo | runs live | checks "was tool called", not real egress; single-server |

Nobody fuses **cross-server auto-pathfinding + confused-deputy/OAuth payload
synthesis + live side-effect proof, run against the defender's own N-server
deployment.** That intersection is `toxitrace`.

> Honest framing: side-effect oracles (VIPER-MCP) and confused-deputy payload
> synthesis (MCP-ITP) each exist *separately*. The contribution here is fusing
> them — cross-server, on your real stack, with an evidence trace — not
> inventing either piece.

## It's a penetration test

Same loop, new target surface:

| Pentest phase | toxitrace |
|---------------|-----------|
| Recon | enumerate MCP servers + tools |
| Map attack surface | capability graph (source / sensitive / sink tags) |
| Craft exploit | poisoned tool-description / injected untrusted input *(v0.2)* |
| Execute | run the real agent in a sandbox *(v0.2)* |
| **Prove impact** | observed file read / egress / token reuse *(v0.2)* |
| Report | ranked chains → OWASP MCP / Agentic Top 10 + severity |

## Install

```bash
git clone <repo> && cd toxitrace
pip install -e .            # or just run with PYTHONPATH=src (zero runtime deps)
```

## Usage

**Static scan** (tools from a manifest):

```bash
toxitrace scan examples/sample_claude_config.json --tools examples/sample_tools.json
```

**Live scan** (enumerate tools over MCP — connects to each server, calls `tools/list`):

```bash
toxitrace scan examples/vuln_lab_config.json --live --min-severity HIGH
```

**Verify** — PROVE the critical chains by observed side effect:

```bash
toxitrace verify examples/vuln_lab_config.json
# spins a sandbox with a canary secret, runs each critical chain against the live
# servers, and confirms exfiltration iff the canary lands in the egress sink.
```

Exit code is non-zero when a CRITICAL chain is found (`scan`) or PROVEN
(`verify`), so it gates a pentest run or CI. The bundled
`examples/vuln_server.py` is a deliberately-vulnerable MCP server (3 roles) that
forms a cross-server `inbox → files → mailer` confused-deputy stack to test
against.

## Roadmap

- **v0.1 — capability graph** *(done)*: config ingest, tool classification,
  ranked candidate cross-server chains, OWASP-mapped report.
- **v0.2 — live enumeration + verified chain** *(done)*: real MCP stdio client,
  deliberately-vulnerable lab, sandbox + canary, side-effect oracle that proves
  `file-exfil` end-to-end (driven by a deterministic ScriptedAgent).
- **v0.3 — real LLM driver + egress capture**: swap ScriptedAgent for an
  Ollama/Anthropic model that *decides* whether to walk the chain (measures real
  susceptibility); netns/proxy egress proof; `token-reuse` chains.
- **v0.4 — OAuth-consent confused deputy** (the least-tooled class).
- **v0.5 — evidence trace + signed JSON/SARIF report** mapped to OWASP
  MCP/Agentic Top 10.
- **v0.6 — optional MCP-server wrapper** so other agents can call `toxitrace`.

## Ethics / legal

Assess only agent stacks you **own or are explicitly authorized to test**. The
dynamic engine (v0.2+) executes real exploit chains; run it against your own
deployment and deliberately-vulnerable labs, never third-party servers without
permission.

## License

MIT.
