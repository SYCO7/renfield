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
                "error": v.error or None,
            }
            for v in verdicts
        ],
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


def render(verdicts, config_path: str, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(verdicts_to_json(verdicts, config_path), indent=2)
    if fmt == "sarif":
        return json.dumps(verdicts_to_sarif(verdicts, config_path), indent=2)
    raise ValueError(f"unknown format {fmt}")
