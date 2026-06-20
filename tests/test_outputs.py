"""JSON + SARIF output shape (pure, no servers needed)."""

from renfield.models import Tool, ToxicChain
from renfield.outputs import verdicts_to_json, verdicts_to_sarif
from renfield.verify import Verdict


def _chain():
    return ToxicChain(
        source=Tool("inbox", "read_message"),
        sink=Tool("web", "http_post"),
        sensitive=Tool("files", "read_file"),
        servers=["files", "inbox", "web"],
        cross_server=True,
        severity="CRITICAL",
        owasp=["Lethal Trifecta", "Cross-Server Confused Deputy"],
        rationale="x",
    )


def _verdicts():
    c = _chain()
    return [
        Verdict(chain=c, exploited=True, evidence="canary left the box",
                attack_class="Network Exfiltration"),
        Verdict(chain=c, exploited=False, evidence="—", attack_class="—"),
    ]


def test_json_shape():
    j = verdicts_to_json(_verdicts(), "cfg.json")
    assert j["tool"] == "renfield"
    assert j["summary"] == {"chains_tested": 2, "proven": 1}
    assert j["findings"][0]["attack_class"] == "Network Exfiltration"
    assert j["findings"][0]["exploited"] is True


def test_sarif_shape():
    s = verdicts_to_sarif(_verdicts(), "cfg.json")
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "Renfield"
    # only the proven verdict becomes a result
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "network-exfiltration"
    assert run["results"][0]["level"] == "error"
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"data-exfiltration", "network-exfiltration", "oauth-consent-confused-deputy"} <= ids
