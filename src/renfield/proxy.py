"""Provenance-gated MCP proxy — ENFORCE the taint barriers at runtime.

Everything else in Renfield is offline analysis: find, prove, measure, recommend.
This is the defensive runtime. The proxy is itself an MCP server the agent talks
to; it fronts the agent's real backend servers, forwards tool calls, and tracks
taint *as it happens*. Once the agent has ingested untrusted content, the lethal
action — an external sink or a destructive/auth tool — is the dangerous one, so
the proxy denies it (or flags it), turning a proven confused-deputy exfil into a
blocked call instead of a leak.

Deployment: point the AGENT at the proxy, and the PROXY at the real config:

    { "mcpServers": { "guarded": { "command": "ren",
        "args": ["proxy", "path/to/real-mcp-config.json"] } } }

The agent should mount ONLY the proxy (not the backends directly), or the gate is
bypassed. The proxy is fail-closed in `block` mode: a denied call returns an error
result the model sees, not silent data loss.

Policies:
  - trifecta  (default): once untrusted content is read, block ANY external/
    destructive action. Simple, safe, matches the threat model.
  - dataflow: block such an action only when its arguments actually carry tainted
    (untrusted- or secret-derived) data. Fewer false positives, needs the secret
    to be visible in the call.
"""

from __future__ import annotations

import json
import os
import sys

from . import __version__
from .classify import classify_tool
from .mcp_client import MCPStdioClient, call_text
from .models import Capability, Tool

PROTOCOL_VERSION = "2025-06-18"
_DANGEROUS = {Capability.EXTERNAL_SINK, Capability.DESTRUCTIVE_SINK}


def _log(msg: str) -> None:
    print(f"[renfield-proxy] {msg}", file=sys.stderr, flush=True)


class GatingProxy:
    """Forwards MCP tool calls to backend servers, gating dangerous ones by taint."""

    def __init__(self, servers, policy: str = "trifecta", mode: str = "block", allow=()):
        self.servers = servers
        self.policy = policy
        self.mode = mode
        self.allow = set(allow or ())
        self.clients: dict = {}
        self.registry: dict = {}          # tool name -> (client, capabilities, toolspec)
        self.untrusted_ingested = False
        self.tainted: set[str] = set()    # secret/untrusted-derived values seen
        self.blocks: list[dict] = []      # audit log of denied calls
        self._started = False

    # --- backend lifecycle -------------------------------------------------
    def start(self):
        if self._started:
            return
        for s in self.servers:
            if not s.command:
                continue
            try:
                client = MCPStdioClient(s.command, s.args, env={**os.environ, **s.env})
                client.start()
                self.clients[s.name] = client
                for td in client.list_tools():
                    name = td.get("name", "")
                    caps = classify_tool(Tool(server=s.name, name=name,
                                              description=td.get("description", "")))
                    if name not in self.registry:   # first registration wins on collision
                        self.registry[name] = (client, caps, td)
                    else:
                        _log(f"name collision: '{name}' also on {s.name} — keeping the first")
            except Exception as exc:  # a dead backend shouldn't crash the proxy
                _log(f"backend {s.name} failed to start: {exc}")
        self._started = True

    def close(self):
        for c in self.clients.values():
            try:
                c.close()
            except Exception:
                pass

    # --- the gate ----------------------------------------------------------
    def _dangerous(self, caps) -> bool:
        return bool(caps & _DANGEROUS)

    def gate(self, name: str, args: dict, caps) -> tuple[bool, str]:
        """Return (blocked, reason) for a tool call given the current taint state."""
        if name in self.allow or not self._dangerous(caps) or not self.untrusted_ingested:
            return False, ""
        if self.policy == "dataflow":
            blob = " ".join(str(v) for v in (args or {}).values())
            if not any(t and t in blob for t in self.tainted):
                return False, ""
            return True, ("tainted data present in arguments after untrusted content "
                          "was ingested")
        return True, ("external/destructive action attempted after untrusted content "
                      "was ingested (lethal-trifecta gate)")

    def _absorb(self, caps, result) -> None:
        """Update taint state from a tool result."""
        text = (call_text(result) or "").strip()
        if Capability.UNTRUSTED_SOURCE in caps:
            self.untrusted_ingested = True
            if text:
                self.tainted.add(text)
        if Capability.SENSITIVE_READ in caps and text:
            self.tainted.add(text)

    # --- the proxied call --------------------------------------------------
    def call(self, name: str, args: dict) -> dict:
        self.start()
        entry = self.registry.get(name)
        if entry is None:
            return {"content": [{"type": "text", "text": f"unknown tool {name}"}],
                    "isError": True}
        client, caps, _td = entry
        blocked, reason = self.gate(name, args or {}, caps)
        if blocked:
            self.blocks.append({"tool": name, "reason": reason})
            _log(f"BLOCKED {name}: {reason}")
            if self.mode == "block":
                return {"content": [{"type": "text", "text":
                        f"DENIED by renfield provenance policy: {name} — {reason}. "
                        f"Gate this tool behind human approval."}], "isError": True}
            _log(f"FLAG (allowed in flag mode) {name}")
        result = client.call_tool(name, args or {})
        self._absorb(caps, result)
        return result

    def tools_list(self) -> list[dict]:
        self.start()
        return [{"name": n, "description": td.get("description", ""),
                 "inputSchema": td.get("inputSchema") or {"type": "object", "properties": {}}}
                for n, (_c, _caps, td) in self.registry.items()]


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 stdio server in front of the proxy
# ---------------------------------------------------------------------------
def _handle(proxy: GatingProxy, msg: dict):
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return _ok(mid, {"protocolVersion": PROTOCOL_VERSION,
                         "capabilities": {"tools": {}},
                         "serverInfo": {"name": "renfield-proxy", "version": __version__}})
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "tools/list":
        return _ok(mid, {"tools": proxy.tools_list()})
    if method == "tools/call":
        params = msg.get("params") or {}
        try:
            return _ok(mid, proxy.call(params.get("name"), params.get("arguments") or {}))
        except Exception as exc:
            return _ok(mid, {"content": [{"type": "text", "text": f"error: {exc}"}],
                             "isError": True})
    if method == "ping":
        return _ok(mid, {})
    if mid is not None:
        return _err(mid, -32601, f"method not found: {method}")
    return None


def _ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(proxy: GatingProxy, stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    try:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = _handle(proxy, msg)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()
    finally:
        proxy.close()
    return 0
