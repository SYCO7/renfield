"""toxitrace — pentest tool for AI agent / MCP infrastructure.

v0.1 scope: ingest an agent's MCP config + tool manifest, classify each tool
(untrusted-source / sensitive-read / external-sink), and build a capability
graph that surfaces candidate cross-server confused-deputy exfiltration chains
(the "lethal trifecta": untrusted input + private data + external sink).

Later versions plant payloads, run the real agent in a sandbox, and PROVE each
chain by observing real side effects (file read, egress, token reuse).
"""

__version__ = "0.2.0"
