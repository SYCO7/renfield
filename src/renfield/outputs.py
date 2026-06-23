"""Machine-readable output: JSON and SARIF 2.1.0.

SARIF is the DevSecOps payoff — `ren verify --format sarif > renfield.sarif` and
upload it with github/codeql-action/upload-sarif, and every proven exploit chain
shows up in the repo's Security tab and as an inline PR annotation, gating merges.
"""

from __future__ import annotations

import json

from . import __version__

INFO_URI = "https://github.com/SYCO7/renfield"

# one SARIF rule per attack class
ATTACK_RULES = {
    "Data Exfiltration": {
        "id": "data-exfiltration",
        "desc": "An untrusted-source tool can steer the agent to read sensitive data "
                "and push it to an external sink.",
    },
    "Network Exfiltration": {
        "id": "network-exfiltration",
        "desc": "Sensitive data physically leaves the host via an outbound network "
                "request driven by attacker-controlled content.",
    },
    "OAuth-Consent Confused Deputy": {
        "id": "oauth-consent-confused-deputy",
        "desc": "The agent uses its own authority to approve an attacker-controlled "
                "OAuth consent / access grant (confused deputy).",
    },
}
_DEFAULT_RULE = {"id": "confused-deputy-chain", "desc": "Cross-server confused-deputy exploit chain."}


def _rule_for(attack_class: str) -> dict:
    return ATTACK_RULES.get(attack_class, _DEFAULT_RULE)


def verdicts_to_json(verdicts, config_path: str) -> dict:
    proven = sum(1 for v in verdicts if v.exploited)
    return {
        "tool": "renfield",
        "version": __version__,
        "config": config_path,
        "summary": {"chains_tested": len(verdicts), "proven": proven},
        "findings": [
            {
                "chain": v.chain.hops(),
                "severity": v.chain.severity,
                "attack_class": v.attack_class,
                "exploited": v.exploited,
                "cross_server": v.chain.cross_server,
                "servers": v.chain.servers,
                "owasp": v.chain.owasp,
                "evidence": v.evidence,
                "provenance": _provenance_json(v),
                "error": v.error or None,
            }
            for v in verdicts
        ],
    }


def _provenance_json(v) -> dict | None:
    p = getattr(v, "provenance", None)
    if p is None:
        return None
    flow = getattr(p, "flow", None)
    return {
        "taint_path": p.path(),
        "tainted": p.tainted,
        "source_ingested": p.source_ingested,
        "secret_read": p.secret_read,
        "secret_at_sink": p.secret_at_sink,
        "causal_order": p.causal_order,
        "causally_attributed": p.causally_attributed,
        "causality_note": p.causality_note or None,
        "multihop": None if flow is None else {
            "path": flow.path_str(),
            "hops": flow.length,
            "laundered": flow.laundered,
            "relays": flow.relays,
        },
    }


def verdicts_to_sarif(verdicts, config_path: str) -> dict:
    rules = [
        {
            "id": r["id"],
            "name": "".join(p.capitalize() for p in r["id"].split("-")),
            "shortDescription": {"text": cls},
            "fullDescription": {"text": r["desc"]},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "mcp", "ai-agent", "prompt-injection"]},
            "helpUri": INFO_URI,
        }
        for cls, r in ATTACK_RULES.items()
    ]
    results = []
    for v in verdicts:
        if not v.exploited:
            continue
        rule = _rule_for(v.attack_class)
        results.append({
            "ruleId": rule["id"],
            "level": "error",
            "message": {"text": f"PROVEN {v.attack_class}: {v.chain.hops()} — {v.evidence}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": config_path}},
                "logicalLocations": [{"fullyQualifiedName": v.chain.hops(), "kind": "function"}],
            }],
            "properties": {
                "attackClass": v.attack_class,
                "severity": v.chain.severity,
                "owasp": v.chain.owasp,
                "servers": v.chain.servers,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Renfield",
                "informationUri": INFO_URI,
                "version": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _multihop_html(prov) -> str:
    flow = getattr(prov, "flow", None) if prov else None
    if flow is None or not flow.laundered:
        return ""
    chips = " → ".join(
        f"<span class='hop {h.role}'>{_esc(h.tool)}</span>" for h in flow.hops
    )
    return (f"<div class='flow'><span class='lbl'>multi-hop "
            f"(laundered via {len(flow.relays)} relay):</span> {chips}</div>")


def _trace_html(trace) -> str:
    if not trace:
        return ""
    rows = []
    for step in trace:
        tool = _esc(step.get("tool", ""))
        obs = _esc(str(step.get("observed", "")).replace("\n", " ")[:120])
        rows.append(f"<tr><td class='t'>{tool}</td><td class='o'>{obs}</td></tr>")
    return ("<details class='trace'><summary>tool-call trace "
            f"({len(trace)} step(s))</summary><table>{''.join(rows)}</table></details>")


def verdicts_to_html(verdicts, config_path: str) -> str:
    """A self-contained, dependency-free HTML evidence report (shareable artifact)."""
    proven = sum(1 for v in verdicts if v.exploited)
    cards = []
    for i, v in enumerate(verdicts, 1):
        ok = v.exploited
        prov = getattr(v, "provenance", None)
        taint = f"<div class='taint'>taint: {_esc(prov.path())}</div>" if (prov and ok) else ""
        cards.append(
            f"<div class='card {'bad' if ok else 'ok'}'>"
            f"<div class='hd'><span class='tag'>{'PROVEN' if ok else 'not proven'}</span>"
            f"<span class='cls'>{_esc(v.attack_class)}</span>#{i}</div>"
            f"<div class='chain'>{_esc(v.chain.hops())}</div>"
            f"<div class='ev'>{_esc(v.evidence) or '—'}</div>"
            f"{taint}"
            f"{_multihop_html(prov) if ok else ''}"
            f"{_trace_html(v.trace) if ok else ''}"
            f"<div class='owasp'>{_esc(', '.join(v.chain.owasp))}</div>"
            f"</div>"
        )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Renfield report — {_esc(config_path)}</title>
<style>
:root{{color-scheme:dark}}
body{{font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem}}
h1{{font-size:1.4rem;margin:0 0 .25rem}} .sub{{color:#8b949e;margin-bottom:1.5rem}}
.summary{{font-size:1.1rem;margin-bottom:1.5rem}}
.summary b{{color:{'#f85149' if proven else '#3fb950'}}}
.card{{border:1px solid #30363d;border-left-width:4px;border-radius:6px;padding:1rem;margin:.75rem 0;background:#161b22}}
.card.bad{{border-left-color:#f85149}} .card.ok{{border-left-color:#3fb950}}
.hd{{display:flex;gap:.75rem;align-items:center;margin-bottom:.5rem}}
.tag{{font-weight:700;text-transform:uppercase;font-size:.75rem;padding:.1rem .5rem;border-radius:4px;background:#21262d}}
.card.bad .tag{{color:#f85149}} .card.ok .tag{{color:#3fb950}}
.cls{{color:#d29922}} .hd #{{margin-left:auto}}
.chain{{font-weight:600;margin:.25rem 0}} .ev{{color:#8b949e}}
.taint{{margin-top:.5rem;color:#58a6ff}} .owasp{{margin-top:.5rem;font-size:.8rem;color:#6e7681}}
.flow{{margin-top:.5rem;font-size:.85rem}} .flow .lbl{{color:#8b949e;margin-right:.4rem}}
.hop{{display:inline-block;padding:.05rem .4rem;border-radius:4px;background:#21262d;margin:.1rem 0}}
.hop.relay{{background:#5a3a1a;color:#f0b860}} .hop.source{{color:#f0883e}}
.hop.sink{{color:#f85149}} .hop.sensitive{{color:#d29922}}
.trace{{margin-top:.6rem;font-size:.8rem}} .trace summary{{cursor:pointer;color:#8b949e}}
.trace table{{border-collapse:collapse;margin-top:.4rem;width:100%}}
.trace td{{border-top:1px solid #21262d;padding:.2rem .5rem;vertical-align:top}}
.trace td.t{{color:#79c0ff;white-space:nowrap}} .trace td.o{{color:#8b949e}}
footer{{margin-top:2rem;color:#6e7681;font-size:.8rem}}
</style></head><body>
<h1>🩸 Renfield — agent pentest report</h1>
<div class="sub">target: {_esc(config_path)} · renfield {_esc(__version__)}</div>
<div class="summary"><b>{proven}/{len(verdicts)}</b> chain(s) PROVEN exploitable by real side effect.</div>
{''.join(cards)}
<footer>Proven by observed side effect (canary egress / integrity loss / privileged action), not text-grading.
Only test agent stacks you own or are authorized to assess.</footer>
</body></html>"""


_HTML_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>:root{{color-scheme:dark}}
body{{font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem}}
h1{{font-size:1.3rem;margin:0 0 1rem}} table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #21262d}}
th{{color:#8b949e;font-weight:600}} .yes{{color:#f85149;font-weight:700}} .no{{color:#3fb950}}
footer{{margin-top:1.5rem;color:#6e7681;font-size:.8rem}}</style></head><body>"""


def leaderboard_to_html(rows) -> str:
    trs = []
    for r in rows:
        if r.get("error"):
            trs.append(f"<tr><td>{_esc(r['label'])}</td><td>err</td>"
                       f"<td>setup failed: {_esc(r['error'])}</td></tr>")
            continue
        cls = ", ".join(r["classes"]) if r["classes"] else "(resisted all)"
        trs.append(f"<tr><td>{_esc(r['label'])}</td>"
                   f"<td class='{'yes' if r['pwned'] else 'no'}'>{r['pwned']}/{r['total']}</td>"
                   f"<td>{_esc(cls)}</td></tr>")
    return (_HTML_HEAD.format(title="Renfield — model susceptibility") +
            "<h1>🩸 Renfield — model susceptibility leaderboard</h1>"
            "<table><tr><th>model</th><th>pwned</th><th>attack classes proven</th></tr>"
            f"{''.join(trs)}</table>"
            "<footer>Higher pwned = more susceptible. Proven by side effect.</footer></body></html>")


def matrix_to_html(rows, techniques) -> str:
    head = "".join(f"<th>{_esc(t)}</th>" for t in techniques)
    trs = []
    for r in rows:
        if r.get("error"):
            trs.append(f"<tr><td>{_esc(r['label'])}</td><td colspan='{len(techniques)+1}'>"
                       f"setup failed: {_esc(r['error'])}</td></tr>")
            continue
        bypass = set(r["bypass"])
        resisted = len(techniques) - len(bypass & set(techniques))
        cells = "".join(
            f"<td class='{'yes' if t in bypass else 'no'}'>{'✓' if t in bypass else '·'}</td>"
            for t in techniques)
        trs.append(f"<tr><td>{_esc(r['label'])}</td><td>{resisted}/{len(techniques)}</td>{cells}</tr>")
    return (_HTML_HEAD.format(title="Renfield — technique matrix") +
            "<h1>🩸 Renfield — model × injection-technique robustness</h1>"
            f"<table><tr><th>model</th><th>resist</th>{head}</tr>{''.join(trs)}</table>"
            "<footer>✓ = technique bypassed the model (proven side effect) · = resisted.</footer></body></html>")


def render(verdicts, config_path: str, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(verdicts_to_json(verdicts, config_path), indent=2)
    if fmt == "sarif":
        return json.dumps(verdicts_to_sarif(verdicts, config_path), indent=2)
    if fmt == "html":
        return verdicts_to_html(verdicts, config_path)
    raise ValueError(f"unknown format {fmt}")
