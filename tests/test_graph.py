from pathlib import Path

from renfield.classify import classify_servers
from renfield.config import attach_tools, load_config, load_tools_manifest
from renfield.graph import build_chains

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _scan():
    servers = load_config(EXAMPLES / "sample_agent_config.json")
    attach_tools(servers, load_tools_manifest(EXAMPLES / "sample_tools.json"))
    classify_servers(servers)
    return build_chains(servers)


def test_finds_critical_cross_server_chain():
    chains = _scan()
    assert chains, "expected at least one candidate chain"
    top = chains[0]
    assert top.severity == "CRITICAL"
    assert top.cross_server


def test_critical_chain_spans_multiple_servers():
    critical = [c for c in _scan() if c.severity == "CRITICAL"]
    assert critical
    # the canonical trifecta: github issue -> filesystem read -> gmail send
    spans = {tuple(c.servers) for c in critical}
    assert any(len(s) >= 2 for s in spans)


def test_source_and_sink_never_identical():
    for c in _scan():
        assert c.source.ref != c.sink.ref
