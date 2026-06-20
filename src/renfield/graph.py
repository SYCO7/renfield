"""Build the capability graph and surface candidate toxic chains.

A toxic chain = an untrusted-source tool whose pulled-in (attacker-controlled)
content can drive the agent to use a *different*, trusted tool to read sensitive
data and/or push it to an external sink. Cross-server chains are the
highest-value finding: that is the confused-deputy / lethal-trifecta class that
isolated single-server scanners structurally cannot see.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .models import Capability, Server, Tool, ToxicChain

_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def _severity(has_sensitive: bool, cross_server: bool) -> str:
    if has_sensitive and cross_server:
        return "CRITICAL"
    if has_sensitive:
        return "HIGH"
    if cross_server:
        return "MEDIUM"
    return "LOW"


def _owasp(has_sensitive: bool) -> list[str]:
    tags = ["Lethal Trifecta", "MCP Tool Poisoning (Indirect Prompt Injection)"]
    if has_sensitive:
        tags.append("Cross-Server Confused Deputy")
    return tags


def _pick_sensitive(sensitives: list[Tool], source: Tool, sink: Tool) -> Tool | None:
    """Prefer a sensitive-read tool on a server other than the source's."""
    if not sensitives:
        return None
    off_source = [t for t in sensitives if t.server != source.server]
    pool = off_source or sensitives
    # prefer one that isn't literally the source or sink tool
    distinct = [t for t in pool if t.ref not in (source.ref, sink.ref)]
    return (distinct or pool)[0]


def build_chains(servers: list[Server]) -> list[ToxicChain]:
    tools = [t for s in servers for t in s.tools]
    sources = [t for t in tools if Capability.UNTRUSTED_SOURCE in t.capabilities]
    sinks = [t for t in tools if Capability.EXTERNAL_SINK in t.capabilities]
    sensitives = [t for t in tools if Capability.SENSITIVE_READ in t.capabilities]

    chains: list[ToxicChain] = []
    for source in sources:
        for sink in sinks:
            if source.ref == sink.ref:
                continue  # same tool as both ends = not an interesting chain
            sensitive = _pick_sensitive(sensitives, source, sink)
            involved = {source.server, sink.server}
            if sensitive:
                involved.add(sensitive.server)
            cross = len(involved) > 1
            sev = _severity(sensitive is not None, cross)
            chains.append(
                ToxicChain(
                    source=source,
                    sink=sink,
                    sensitive=sensitive,
                    servers=sorted(involved),
                    cross_server=cross,
                    severity=sev,
                    owasp=_owasp(sensitive is not None),
                    rationale=_rationale(source, sensitive, sink, cross),
                )
            )

    chains.sort(
        key=lambda c: (_SEVERITY_RANK[c.severity], c.cross_server, c.hops()),
        reverse=True,
    )
    return chains


def chain_nodes(chain: ToxicChain) -> set[str]:
    """The tools a chain depends on — removing ANY one breaks the chain."""
    nodes = {chain.source.ref, chain.sink.ref}
    if chain.sensitive is not None:
        nodes.add(chain.sensitive.ref)
    return nodes


@dataclass
class Remediation:
    cut: list[str]              # capabilities to remove/gate
    broken: int                 # chains this cut breaks
    remaining: list[ToxicChain]  # chains still exploitable after the cut (should be empty)

    @property
    def proven(self) -> bool:
        return not self.remaining


def minimal_fix(chains: list[ToxicChain]) -> Remediation:
    """Smallest set of tools to remove so EVERY chain is broken (greedy hitting set).

    Each chain breaks if any of its tools is removed, so this is a minimum hitting
    set over the chains' tool sets. NP-hard in general, but chains are few; greedy
    (always remove the tool covering the most still-live chains) is the standard
    log-approximation and is exact for the common shared-source case. This is the
    minimal least-privilege change that makes every proven attack impossible.
    """
    live = [chain_nodes(c) for c in chains]
    cut: list[str] = []
    while live:
        freq = Counter(tool for nodes in live for tool in nodes)
        # most-covering tool; deterministic tiebreak by name
        best = max(freq, key=lambda t: (freq[t], t))
        cut.append(best)
        live = [nodes for nodes in live if best not in nodes]

    cut_set = set(cut)
    remaining = [c for c in chains if not (chain_nodes(c) & cut_set)]
    return Remediation(cut=sorted(cut), broken=len(chains) - len(remaining), remaining=remaining)


def _rationale(source: Tool, sensitive: Tool | None, sink: Tool, cross: bool) -> str:
    span = "across servers" if cross else "within one server"
    if sensitive:
        return (
            f"Attacker-controlled content from {source.ref} can steer the agent to "
            f"read sensitive data via {sensitive.ref} and exfiltrate it through "
            f"{sink.ref} ({span})."
        )
    return (
        f"Attacker-controlled content from {source.ref} can steer the agent to "
        f"act through {sink.ref} ({span})."
    )
