"""Minimal-fix engine: smallest capability cut that breaks every critical chain."""

import sys
from pathlib import Path

from renfield.classify import classify_servers
from renfield.graph import build_chains, chain_nodes, minimal_fix
from renfield.live import enumerate_tools
from renfield.models import Server

VULN = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_server.py")


def _criticals():
    roles = ["inbox", "files", "mailer", "web", "oauth"]
    servers = [Server(r, sys.executable, [VULN], {"TOXI_ROLE": r}) for r in roles]
    enumerate_tools(servers)
    classify_servers(servers)
    return [c for c in build_chains(servers) if c.severity == "CRITICAL"]


def test_minimal_fix_breaks_all_chains():
    crit = _criticals()
    assert crit, "expected critical chains in the full lab"
    rem = minimal_fix(crit)
    assert rem.proven is True
    assert rem.remaining == []
    assert rem.broken == len(crit)


def test_single_shared_source_is_one_capability_fix():
    # every chain's only untrusted source is inbox.read_message -> removing it
    # alone breaks all of them (the minimal fix is a single capability).
    rem = minimal_fix(_criticals())
    assert rem.cut == ["inbox.read_message"]


def test_chain_nodes_contains_endpoints():
    c = _criticals()[0]
    nodes = chain_nodes(c)
    assert c.source.ref in nodes and c.sink.ref in nodes
