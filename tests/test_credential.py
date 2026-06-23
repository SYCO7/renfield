"""Credential / token-reuse confused deputy: the user's credential is replayed to
authenticate a privileged action for the attacker (distinct from passive exfil)."""

import sys
from pathlib import Path

from renfield.classify import classify_servers, classify_tool
from renfield.graph import build_chains
from renfield.live import enumerate_tools
from renfield.models import Capability, Server, Tool
from renfield.verify import verify_chain

VULN = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_server.py")


def test_deploy_tool_classified_as_sink():
    caps = classify_tool(Tool(server="cicd", name="trigger_deploy",
                              description="Trigger a deployment with an API key"))
    assert Capability.EXTERNAL_SINK in caps


def test_api_key_tool_classified_sensitive():
    caps = classify_tool(Tool(server="vault", name="read_api_key",
                              description="Read the user's stored API key"))
    assert Capability.SENSITIVE_READ in caps


def _credential_lab():
    servers = [Server("inbox", sys.executable, [VULN], {"TOXI_ROLE": "inbox"}),
               Server("vault", sys.executable, [VULN], {"TOXI_ROLE": "vault"}),
               Server("cicd", sys.executable, [VULN], {"TOXI_ROLE": "cicd"})]
    enumerate_tools(servers)
    classify_servers(servers)
    return servers


def test_credential_reuse_proven_distinct_from_exfil():
    servers = _credential_lab()
    chain = next(c for c in build_chains(servers)
                 if c.severity == "CRITICAL" and c.sink.name == "trigger_deploy")
    verdict = verify_chain(chain, servers)
    assert verdict.exploited is True
    assert verdict.attack_class == "Credential/Token Reuse"
    assert "replayed" in verdict.evidence
