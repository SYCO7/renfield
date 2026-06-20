"""Render a clean, monochrome text report of the capability graph + chains."""

from __future__ import annotations

from .models import Capability, Server, ToxicChain

_RULE = "=" * 66
_THIN = "-" * 66
_BADGE = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED ]", "LOW": "[LOW ]"}


def render(servers: list[Server], chains: list[ToxicChain], mode: str = "static") -> str:
    out: list[str] = []
    out.append(_RULE)
    out.append(f"toxitrace — MCP agent capability assessment ({mode} enumeration)")
    out.append(_RULE)

    tools = [t for s in servers for t in s.tools]
    out.append(f"servers: {len(servers)}    tools: {len(tools)}")
    out.append("")

    out.append("CAPABILITY MAP")
    out.append(_THIN)
    if not tools:
        out.append("  no tool data — pass --tools <manifest.json> "
                   "(live MCP enumeration arrives in v0.2)")
    for server in servers:
        out.append(f"  {server.name}")
        for tool in server.tools:
            out.append(f"    - {tool.name:<24} {tool.tag_str()}")
    out.append("")

    crit = sum(1 for c in chains if c.severity == "CRITICAL")
    cross = sum(1 for c in chains if c.cross_server)
    out.append("TOXIC CHAINS")
    out.append(_THIN)
    out.append(f"  {len(chains)} candidate chain(s)  |  "
               f"{crit} critical  |  {cross} cross-server")
    out.append("")

    for i, c in enumerate(chains, 1):
        scope = "CROSS-SERVER" if c.cross_server else "single-server"
        out.append(f"{_BADGE[c.severity]} #{i}  {scope}  servers={'+'.join(c.servers)}")
        out.append(f"        {c.hops()}")
        out.append(f"        {c.rationale}")
        out.append(f"        OWASP: {', '.join(c.owasp)}")
        out.append("")

    out.append(_THIN)
    out.append("NOTE: `scan` reports *candidate* chains from capability analysis.")
    out.append("      Run `toxitrace verify` to PROVE a chain by planting a payload")
    out.append("      and observing a real side effect (file read / egress / token "
               "reuse).")
    out.append("      Only assess agent stacks you own or are authorized to test.")
    out.append(_RULE)
    return "\n".join(out)
