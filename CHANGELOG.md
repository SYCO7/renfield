# Changelog

All notable changes to Renfield. Versions follow the roadmap in the README.
The PyPI distribution is `renfield-mcp`; the CLI is `ren`.

## [1.7.2]
- **PyPI-ready packaging.** The vulnerable lab now ships *inside* the wheel at
  `renfield/lab/vuln_server.py`, so `ren quickstart` works after `pip install`
  (previously it relied on the repo's `examples/` dir, which isn't distributed).
  Richer pyproject metadata (project URLs, full classifiers), a `PUBLISHING.md`
  runbook, and a test keeping the bundled lab byte-identical to the example copy.

## [1.7.1]
- **Configurable Ollama per-turn timeout** via `RENFIELD_OLLAMA_TIMEOUT` (seconds;
  default 120). Grammar-constrained tool-calling on CPU can run several seconds per
  token, blowing past the old hard-coded limit — local users can now raise it.
- **First real measured runs** documented in the README: `ren verify` with qwen2.5:3b
  scored 1/3 chains proven, and the model *hallucinated* an exfiltration the side-effect
  oracle correctly rejected. The `ren redteam` matrix with the smaller qwen2.5:0.5b
  scored 21/21 "resisted" — but the trace shows it was too weak to chain the tool calls,
  not refusing: capability gates exploitability, and side-effect grounding tells the
  difference between "safe" and "incapable".

## [1.7.0]
- **Proxy audit log + per-session provenance report.** The gating proxy now records
  every proxied call (`--audit-log <path.jsonl>`, durable) and can emit a session
  report on shutdown (`--report <path>`; format from extension — text/json/html)
  summarising the calls, what was ingested, and what was blocked/flagged. New
  `ren proxy-report <log.jsonl>` renders a report from a saved audit log after the fact.

## [1.6.0]
- **Provenance-gating MCP proxy** (`ren proxy <config>`) — Renfield's first
  *defensive runtime*. It fronts the agent's real MCP servers, tracks taint as
  calls happen, and **blocks the lethal action at call time**: once untrusted
  content has been read, an external-sink / destructive / auth-action call is
  denied (`block`, fail-closed) or logged (`flag`). Policies: `trifecta` (block
  any dangerous action after untrusted ingest) and `dataflow` (block only when
  tainted data is in the call arguments). `--allow` whitelists specific tools.
  Point the agent at the proxy; the proxy fronts the real config.

## [1.5.0]
- **Taint-aware remediation.** `remediate --keep <tool>` protects a load-bearing
  tool (e.g. the agent's whole-purpose source) from the cut, forcing the minimal
  fix downstream — gate the relay/sink/sensitive instead of the source — and flags
  any chain that becomes *unbreakable* by removal alone (gate it behind approval).
- **`remediate --prove`** surfaces **taint barriers**: relay tools that laundered a
  proven exploit and should also be gated (provenance check / human approval), as
  defense in depth beyond the guaranteed minimal cut.

## [1.4.0]
- **HTML reports for `audit` and `compare`** — `ren audit --format html` and
  `ren compare --format html` (leaderboard *and* `--matrix`) emit self-contained,
  dependency-free reports (matching `verify --format html`).
- **Taint + tool-call trace in the HTML** — proven findings now render the full
  tool-call trace and the multi-hop taint path, with relay (laundering) hops
  highlighted — so you can see *how* the data flowed, not just that it leaked.

## [1.3.0]
- **Multi-hop taint tracking** — taint is followed through *arbitrary intermediate
  tool results*, not just the fixed source → sensitive → sink shape. Detects taint
  *laundering* (the agent stashing data in a notes/store tool and reading it back
  before exfil). Driver- and length-agnostic; surfaced in `verify` text and JSON
  (`provenance.multihop`). New `notes.save_note/load_note` relay lab role.
- Verification now exposes the **whole mesh** to the agent driver (a real agent can
  call any tool), which is what makes multi-hop laundering observable.

## [1.2.0]
- **Credential / Token-Reuse confused deputy** — new attack class proven by side
  effect: the user's credential is *replayed to authenticate a privileged action*
  (e.g. a deploy) for the attacker — distinct from passive exfiltration. New lab
  roles `vault.read_api_key` + `cicd.trigger_deploy` and `examples/vuln_lab_credential.json`.

## [1.1.0]
- **Destructive Action** attack class — attacker content steers the agent to
  delete/overwrite data; proven by the integrity-target file being gone. New
  `fs.delete_file` lab role + `examples/vuln_lab_destructive.json`.
- **Tool shadowing** — static detection of cross-server tool-name collisions
  (`ren scan`, `renfield_scan`).
- **`compare --matrix`** — model × injection-technique robustness grid.
- **`verify --format html`** — self-contained HTML evidence report.

## [1.0.0]
- **Taint / provenance** — every proven leak carries a labelled taint path
  `source[SRC] ⇒ sensitive[CANARY] ⇒ sink[egress]`.
- **Causal attribution** (`verify --causality`) — a benign control run attributes
  the leak to the untrusted source (leak only under injection ⇒ caused by it).

## [0.10.0]
- **`ren redteam`** — injection-technique library (direct, authority, roleplay,
  urgency, data_smuggle, polite_indirect, obfuscation); reports which techniques
  bypass a model, by side effect.
- Parallel server enumeration + parallel technique matrix.

## [0.9.0]
- **MCP-server mode** (`ren serve`) — Renfield runs as an MCP server any agent can
  call as a tool (`renfield_audit/scan/verify/remediate`); self-excludes itself.
- **Universal agent discovery** (`ren agents`, auto-detect) — Claude Code/Desktop,
  Cursor, Windsurf, Cline, Continue, VS Code, Zed, Gemini CLI.
- **`ren audit`** — one-shot scan → prove → minimal-fix in a single enumeration.
- PyPI distribution renamed to `renfield-mcp`.

## [0.8.0 and earlier]
- See the roadmap in the README for v0.1–v0.8 (capability graph, live enumeration +
  side-effect oracle, real-LLM driver, multi-provider, egress capture + OAuth-consent
  class + model leaderboard, JSON/SARIF + CI, minimal-fix remediation).
