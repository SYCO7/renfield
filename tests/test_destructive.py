"""Destructive-action attack class: untrusted source -> destructive sink, proven
by integrity loss (the victim file is actually gone)."""

import sys
from pathlib import Path

from renfield.classify import classify_servers, classify_tool
from renfield.graph import build_chains
from renfield.live import enumerate_tools
from renfield.models import Capability, Server, Tool
from renfield.verify import verify_chain

VULN = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_server.py")


def test_delete_tool_is_classified_destructive():
    caps = classify_tool(Tool(server="fs", name="delete_file",
                              description="Delete a file from disk"))
    assert Capability.DESTRUCTIVE_SINK in caps


def _destructive_lab():
    servers = [Server("inbox", sys.executable, [VULN], {"TOXI_ROLE": "inbox"}),
               Server("fs", sys.executable, [VULN], {"TOXI_ROLE": "fs"})]
    enumerate_tools(servers)
    classify_servers(servers)
    return servers


def test_destructive_chain_is_built_cross_server():
    servers = _destructive_lab()
    chains = build_chains(servers)
    dchains = [c for c in chains if c.kind == "destructive"]
    assert dchains, "expected an inbox -> fs.delete_file destructive chain"
    c = dchains[0]
    assert c.sink.name == "delete_file"
    assert c.sensitive is None
    assert c.cross_server and c.severity == "CRITICAL"


def test_destructive_chain_proven_by_integrity_loss():
    servers = _destructive_lab()
    chain = next(c for c in build_chains(servers) if c.kind == "destructive")
    verdict = verify_chain(chain, servers)
    assert verdict.exploited is True
    assert verdict.attack_class == "Destructive Action"
    assert "data loss" in verdict.evidence
