"""Renfield — penetration testing for AI agents.

Does your AI agent say yes to attackers? Renfield points at an agent's own MCP
tool mesh, finds the untrusted-source -> sensitive-read -> external-sink chains
that let injected content steer the agent into stealing and leaking data across
server boundaries (the cross-server confused-deputy / lethal-trifecta class),
PROVES each by observing a real side effect in a sandbox (the canary secret
reaching an egress sink), and — with the LLM driver — measures whether a real
model actually falls for it.

Pipeline: config ingest -> live MCP enumeration -> capability graph -> candidate
chains -> dynamic verification (sandbox + side-effect oracle) -> report.
"""

__version__ = "1.7.1"
