"""Build the capability graph and surface candidate toxic chains.

A toxic chain = an untrusted-source tool whose pulled-in (attacker-controlled)
content can drive the agent to use a *different*, trusted tool to read sensitive
data and/or push it to an external sink. Cross-server chains are the
highest-value finding: that is the confused-deputy / lethal-trifecta class that
isolated single-server scanners structurally cannot see.
"""

from __future__ import annotations

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
