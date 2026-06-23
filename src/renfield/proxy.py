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
import time

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

    def __init__(self, servers, policy: str = "trifecta", mode: str = "block",
                 allow=(), audit_log: str | None = None):
        self.servers = servers
        self.policy = policy
        self.mode = mode
        self.allow = set(allow or ())
        self.audit_log = audit_log        # path to append JSONL events to (durable)
        self.clients: dict = {}
        self.registry: dict = {}          # tool name -> (client, capabilities, toolspec)
        self.untrusted_ingested = False
        self.tainted: set[str] = set()    # secret/untrusted-derived values seen
        self.blocks: list[dict] = []      # denied calls (subset of events)
        self.events: list[dict] = []      # every proxied call (the audit trail)
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
    def _record(self, tool, decision, reason, dangerous, ingested_before) -> None:
        event = {
            "seq": len(self.events) + 1,
            "ts": time.time(),
            "tool": tool,
            "decision": decision,                 # allowed | blocked | flagged
            "reason": reason or None,
            "dangerous": dangerous,
            "untrusted_ingested_before": ingested_before,
        }
        self.events.append(event)
        if decision in ("blocked", "flagged"):
            self.blocks.append({"tool": tool, "reason": reason, "decision": decision})
        if self.audit_log:
            try:
                with open(self.audit_log, "a") as f:
                    f.write(json.dumps(event) + "\n")
            except OSError as exc:
                _log(f"could not write audit log: {exc}")

    def call(self, name: str, args: dict) -> dict:
        self.start()
        entry = self.registry.get(name)
        if entry is None:
            self._record(name, "allowed", "unknown tool", False, self.untrusted_ingested)
            return {"content": [{"type": "text", "text": f"unknown tool {name}"}],
                    "isError": True}
        client, caps, _td = entry
        ingested_before = self.untrusted_ingested
        blocked, reason = self.gate(name, args or {}, caps)
        if blocked:
            decision = "blocked" if self.mode == "block" else "flagged"
            self._record(name, decision, reason, self._dangerous(caps), ingested_before)
            _log(f"{decision.upper()} {name}: {reason}")
            if self.mode == "block":
                return {"content": [{"type": "text", "text":
                        f"DENIED by renfield provenance policy: {name} — {reason}. "
                        f"Gate this tool behind human approval."}], "isError": True}
        else:
            self._record(name, "allowed", "", self._dangerous(caps), ingested_before)
        result = client.call_tool(name, args or {})
        self._absorb(caps, result)
        return result

    def session_report(self) -> dict:
        """A structured per-session provenance report of what the proxy saw."""
        blocked = [e for e in self.events if e["decision"] == "blocked"]
        flagged = [e for e in self.events if e["decision"] == "flagged"]
        dangerous_after = [e for e in self.events
                           if e["dangerous"] and e["untrusted_ingested_before"]]
        if blocked:
            verdict = f"{len(blocked)} dangerous call(s) BLOCKED after untrusted ingest"
        elif flagged:
            verdict = f"{len(flagged)} dangerous call(s) FLAGGED (flag mode — not blocked)"
        elif dangerous_after:
            verdict = "dangerous calls occurred after untrusted ingest but were allowed"
        else:
            verdict = "no dangerous action after untrusted content — clean session"
        return {
            "tool": "renfield-proxy",
            "version": __version__,
            "policy": self.policy,
            "mode": self.mode,
            "calls": len(self.events),
            "untrusted_ingested": self.untrusted_ingested,
            "allowed": sum(1 for e in self.events if e["decision"] == "allowed"),
            "blocked": [e["tool"] for e in blocked],
            "flagged": [e["tool"] for e in flagged],
            "verdict": verdict,
            "events": self.events,
        }

    def tools_list(self) -> list[dict]:
        self.start()
        return [{"name": n, "description": td.get("description", ""),
                 "inputSchema": td.get("inputSchema") or {"type": "object", "properties": {}}}
                for n, (_c, _caps, td) in self.registry.items()]


def report_from_events(events: list[dict], policy="?", mode="?") -> dict:
    """Rebuild a session report from a saved JSONL audit log (after the fact)."""
    p = GatingProxy([], policy=policy, mode=mode)
    p.events = list(events)
    # best-effort from the log: ingest is visible once any later call records it
    p.untrusted_ingested = (
        any(e.get("untrusted_ingested_before") for e in events)
        or any(e.get("decision") in ("blocked", "flagged") for e in events)
    )
    return p.session_report()


def render_session_report(report: dict, fmt: str = "text") -> str:
    """Render a session report as text or a self-contained HTML page."""
    if fmt == "json":
        return json.dumps(report, indent=2)
    if fmt == "html":
        return _session_html(report)
    rule = "=" * 66
    out = [rule, "renfield-proxy — session provenance report", rule,
           f"policy: {report['policy']}   mode: {report['mode']}   "
           f"calls: {report['calls']}",
           f"untrusted content ingested: {report['untrusted_ingested']}",
           f"verdict: {report['verdict']}", "-" * 66]
    for e in report["events"]:
        mark = {"blocked": "[BLOCKED]", "flagged": "[FLAGGED]", "allowed": "[ ok    ]"}[e["decision"]]
        danger = " (dangerous)" if e["dangerous"] else ""
        out.append(f"  {e['seq']:>3} {mark} {e['tool']}{danger}")
        if e.get("reason"):
            out.append(f"        - {e['reason']}")
    out.append(rule)
    return "\n".join(out)


def _esc(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _session_html(report: dict) -> str:
    rows = []
    for e in report["events"]:
        cls = {"blocked": "blk", "flagged": "flg", "allowed": "ok"}[e["decision"]]
        rows.append(f"<tr class='{cls}'><td>{e['seq']}</td><td>{_esc(e['tool'])}</td>"
                    f"<td>{e['decision']}</td><td>{_esc(e.get('reason') or '')}</td></tr>")
    blocked = report["blocked"]
    return (f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>renfield-proxy session</title><style>:root{{color-scheme:dark}}
body{{font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem}}
h1{{font-size:1.3rem;margin:0 0 .5rem}} .v{{font-size:1.05rem;margin:.5rem 0 1rem;color:{'#f85149' if blocked else '#3fb950'}}}
table{{border-collapse:collapse;width:100%}} td,th{{padding:.35rem .6rem;border-bottom:1px solid #21262d;text-align:left}}
tr.blk td{{color:#f85149}} tr.flg td{{color:#d29922}} tr.ok td{{color:#8b949e}}
</style></head><body><h1>🩸 renfield-proxy — session report</h1>
<div class="sub">policy {_esc(report['policy'])} · mode {_esc(report['mode'])} · {report['calls']} calls</div>
<div class="v">{_esc(report['verdict'])}</div>
<table><tr><th>#</th><th>tool</th><th>decision</th><th>reason</th></tr>{''.join(rows)}</table>
</body></html>""")


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


def serve(proxy: GatingProxy, stdin=None, stdout=None, report_path: str | None = None) -> int:
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
        if report_path:
            fmt = "html" if report_path.endswith(".html") else (
                "json" if report_path.endswith(".json") else "text")
            try:
                with open(report_path, "w") as f:
                    f.write(render_session_report(proxy.session_report(), fmt))
                _log(f"wrote session report -> {report_path}")
            except OSError as exc:
                _log(f"could not write session report: {exc}")
    return 0
