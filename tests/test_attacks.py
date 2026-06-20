"""v0.5 attack classes: network exfiltration + OAuth-consent confused deputy,
plus the model-leaderboard renderer. All proven with the deterministic driver
(no live model / API key needed).
"""

import sys
from pathlib import Path

from renfield.classify import classify_servers
from renfield.graph import build_chains
from renfield.live import enumerate_tools
from renfield.models import Server
from renfield.report import render_leaderboard
from renfield.verify import verify_chain

VULN = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_server.py")


def _servers(roles):
    return [Server(r, sys.executable, [VULN], {"TOXI_ROLE": r}) for r in roles]


def _chain_with_sink(servers, sink_name):
    enumerate_tools(servers)
    classify_servers(servers)
    for c in build_chains(servers):
        if c.sink.name == sink_name and c.severity == "CRITICAL":
            return c
    raise AssertionError(f"no critical chain with sink {sink_name}")


def test_network_exfiltration_proven():
    servers = _servers(["inbox", "files", "web"])
    chain = _chain_with_sink(servers, "http_post")
    verdict = verify_chain(chain, servers)
    assert verdict.exploited is True
    assert verdict.attack_class == "Network Exfiltration"
    assert "left the box" in verdict.evidence


def test_oauth_consent_confused_deputy_proven():
    servers = _servers(["inbox", "files", "oauth"])
    chain = _chain_with_sink(servers, "approve_consent")
    verdict = verify_chain(chain, servers)
    assert verdict.exploited is True
    assert verdict.attack_class == "OAuth-Consent Confused Deputy"


def test_leaderboard_render():
    rows = [
        {"label": "scripted", "total": 3, "pwned": 3,
         "classes": ["Data Exfiltration", "Network Exfiltration",
                     "OAuth-Consent Confused Deputy"]},
        {"label": "ollama:qwen2.5:7b", "total": 3, "pwned": 0, "classes": []},
        {"label": "openai:gpt-4o", "total": 3, "pwned": 0, "classes": [],
         "error": "no api key"},
    ]
    out = render_leaderboard(rows)
    assert "leaderboard" in out
    assert "3/3" in out and "0/3" in out
    assert "(resisted all)" in out
    assert "setup failed" in out
