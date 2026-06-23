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
    return {
        "taint_path": p.path(),
        "tainted": p.tainted,
        "source_ingested": p.source_ingested,
        "secret_read": p.secret_read,
        "secret_at_sink": p.secret_at_sink,
        "causal_order": p.causal_order,
        "causally_attributed": p.causally_attributed,
        "causality_note": p.causality_note or None,
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


def verdicts_to_html(verdicts, config_path: str) -> str:
    """A self-contained, dependency-free HTML evidence report (shareable artifact)."""
    proven = sum(1 for v in verdicts if v.exploited)
    cards = []
    for i, v in enumerate(verdicts, 1):
        ok = v.exploited
        prov = getattr(v, "provenance", None)
        taint = f"<div class='taint'>{_esc(prov.path())}</div>" if (prov and ok) else ""
        cards.append(
            f"<div class='card {'bad' if ok else 'ok'}'>"
            f"<div class='hd'><span class='tag'>{'PROVEN' if ok else 'not proven'}</span>"
            f"<span class='cls'>{_esc(v.attack_class)}</span>#{i}</div>"
            f"<div class='chain'>{_esc(v.chain.hops())}</div>"
            f"<div class='ev'>{_esc(v.evidence) or '—'}</div>"
            f"{taint}"
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
footer{{margin-top:2rem;color:#6e7681;font-size:.8rem}}
</style></head><body>
<h1>🩸 Renfield — agent pentest report</h1>
<div class="sub">target: {_esc(config_path)} · renfield {_esc(__version__)}</div>
<div class="summary"><b>{proven}/{len(verdicts)}</b> chain(s) PROVEN exploitable by real side effect.</div>
{''.join(cards)}
<footer>Proven by observed side effect (canary egress / integrity loss / privileged action), not text-grading.
Only test agent stacks you own or are authorized to assess.</footer>
</body></html>"""


def render(verdicts, config_path: str, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(verdicts_to_json(verdicts, config_path), indent=2)
    if fmt == "sarif":
        return json.dumps(verdicts_to_sarif(verdicts, config_path), indent=2)
    if fmt == "html":
        return verdicts_to_html(verdicts, config_path)
    raise ValueError(f"unknown format {fmt}")
