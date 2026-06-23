"""Tool-shadowing / name-collision detection (OWASP MCP: Tool Shadowing).

When two servers in the same mesh expose a tool with the *same name*, the agent
must disambiguate by name alone — and a malicious or compromised server can
register a colliding name to intercept calls meant for the trusted one (or to
poison tool selection). MCP has no global namespace, so this is a real,
purely-static finding: no execution needed, just the enumerated tool list.

A collision is HIGH severity when at least one of the colliding tools carries a
sink/sensitive capability (interception has real impact) and MEDIUM otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Capability, Server


@dataclass
class Shadow:
    name: str               # the colliding tool name
    servers: list[str]      # servers that each define a tool with this name
    severity: str           # HIGH if any colliding tool is sink/sensitive, else MEDIUM
    impactful: bool         # at least one colliding tool can read secrets or push data

    @property
    def refs(self) -> list[str]:
        return [f"{s}.{self.name}" for s in self.servers]


_IMPACT = {Capability.SENSITIVE_READ, Capability.EXTERNAL_SINK, Capability.UNTRUSTED_SOURCE}


def find_shadows(servers: list[Server]) -> list[Shadow]:
    """Return tool names defined by more than one server (potential shadowing)."""
    by_name: dict[str, list] = {}
    for s in servers:
        for t in s.tools:
            by_name.setdefault(t.name, []).append(t)

    shadows: list[Shadow] = []
    for name, tools in by_name.items():
        owners = sorted({t.server for t in tools})
        if len(owners) < 2:
            continue  # same name on one server isn't a cross-server collision
        impactful = any(t.capabilities & _IMPACT for t in tools)
        shadows.append(Shadow(
            name=name,
            servers=owners,
            severity="HIGH" if impactful else "MEDIUM",
            impactful=impactful,
        ))
    shadows.sort(key=lambda sh: (sh.severity != "HIGH", sh.name))
    return shadows
