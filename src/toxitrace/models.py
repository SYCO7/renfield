"""Core data model: servers, tools, capability tags, toxic chains."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Capability(str, Enum):
    """What an MCP tool can do in an exfiltration chain."""

    UNTRUSTED_SOURCE = "untrusted-source"  # pulls in attacker-influenceable data
    SENSITIVE_READ = "sensitive-read"      # reads secrets / private data
    EXTERNAL_SINK = "external-sink"        # can push data off the box
    BENIGN = "benign"


@dataclass
class Tool:
    server: str
    name: str
    description: str = ""
    capabilities: set[Capability] = field(default_factory=set)

    @property
    def ref(self) -> str:
        return f"{self.server}.{self.name}"

    def tag_str(self) -> str:
        if not self.capabilities or self.capabilities == {Capability.BENIGN}:
            return "benign"
        order = [
            Capability.UNTRUSTED_SOURCE,
            Capability.SENSITIVE_READ,
            Capability.EXTERNAL_SINK,
        ]
        return ", ".join(c.value for c in order if c in self.capabilities)


@dataclass
class Server:
    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    tools: list[Tool] = field(default_factory=list)


@dataclass
class ToxicChain:
    """A candidate source -> (sensitive) -> sink exfiltration path."""

    source: Tool
    sink: Tool
    sensitive: Tool | None
    servers: list[str]
    cross_server: bool
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    owasp: list[str]
    rationale: str

    def hops(self) -> str:
        mids = [self.sensitive.ref] if self.sensitive else []
        return " -> ".join([self.source.ref, *mids, self.sink.ref])
