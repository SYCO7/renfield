# Changelog

All notable changes to Renfield. Versions follow the roadmap in the README.
The PyPI distribution is `renfield-mcp`; the CLI is `ren`.

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
