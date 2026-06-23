"""Renfield as an MCP server — let ANY agent run the pentest as a tool.

This is the inverse of `mcp_client.py`: instead of *driving* MCP servers, we
*are* one. A minimal, zero-dependency JSON-RPC 2.0 stdio server that exposes
Renfield's pipeline (scan / verify / remediate / audit) as MCP tools. Any
MCP-capable coding agent — Claude Code, Cursor, Cline, Windsurf, Continue, Zed,
VS Code — can mount it and say "audit my agent", and the agent calls the tool.

    {
      "mcpServers": {
        "renfield": { "command": "ren", "args": ["serve"] }
      }
    }

SAFETY — self-exclusion: the whole point of Renfield is to test an MCP mesh, so
if it is itself mounted in the config under test we would recurse / test
ourselves. `_strip_self()` removes any server whose command launches Renfield
before we ever enumerate. We also refuse to enumerate the very config file we
were told to serve from, defensively.

Treat the target config as trusted input; run untrusted third-party servers in a
throwaway VM/container (see SECURITY.md).
"""

from __future__ import annotations

import json
import sys

from . import __version__
from .classify import classify_servers
from .config import load_config
from .graph import build_chains, minimal_fix
from .live import enumerate_tools
from .verify import verify_chain

PROTOCOL_VERSION = "2025-06-18"

# ---------------------------------------------------------------------------
# self-exclusion: never let Renfield enumerate / attack its own server entry
# ---------------------------------------------------------------------------
_SELF_MARKERS = ("renfield", "ren serve", "mcp_server")


def _is_self(server) -> bool:
    blob = " ".join([str(server.command), *(str(a) for a in (server.args or []))]).lower()
    if "serve" in blob and "ren" in blob:
        return True
    return any(m in blob for m in _SELF_MARKERS)


def _strip_self(servers):
    kept = [s for s in servers if not _is_self(s)]
    dropped = [s.name for s in servers if _is_self(s)]
    return kept, dropped


# ---------------------------------------------------------------------------
# the pentest pipeline, returned as structured data (not printed)
# ---------------------------------------------------------------------------
def _prepare(config_path):
    servers, dropped = _strip_self(load_config(config_path))
    errors = [f"{r.server}: {r.error}" for r in enumerate_tools(servers) if not r.ok]
    classify_servers(servers)
    return servers, dropped, errors


def _capability_map(servers):
    return {
        s.name: [{"tool": t.name, "capabilities": t.tag_str()} for t in s.tools]
        for s in servers
    }


def _chain_dict(c, *, exploited=None, attack_class=None, evidence=None, provenance=None):
    d = {
        "chain": c.hops(),
        "severity": c.severity,
        "cross_server": c.cross_server,
        "servers": c.servers,
        "owasp": c.owasp,
    }
    if exploited is not None:
        d.update(exploited=exploited, attack_class=attack_class, evidence=evidence)
        if provenance is not None:
            d["taint_path"] = provenance.path()
            d["tainted"] = provenance.tainted
    return d


def tool_scan(config_path, **_):
    servers, dropped, errors = _prepare(config_path)
    chains = build_chains(servers)
    crit = [c for c in chains if c.severity == "CRITICAL"]
    return {
        "config": config_path,
        "servers": len(servers),
        "self_excluded": dropped,
        "enumeration_errors": errors,
        "capability_map": _capability_map(servers),
        "candidate_chains": len(chains),
        "critical_chains": [_chain_dict(c) for c in crit],
    }


def tool_verify(config_path, max=6, driver=None, **_):
    servers, dropped, errors = _prepare(config_path)
    crit = [c for c in build_chains(servers) if c.severity == "CRITICAL"][: int(max)]
    verdicts = [verify_chain(c, servers, driver=driver) for c in crit]
    proven = [v for v in verdicts if v.exploited]
    return {
        "config": config_path,
        "self_excluded": dropped,
        "chains_tested": len(verdicts),
        "proven": len(proven),
        "findings": [
            _chain_dict(v.chain, exploited=v.exploited,
                        attack_class=v.attack_class, evidence=v.evidence,
                        provenance=v.provenance)
            for v in verdicts
        ],
        "exploitable": len(proven) > 0,
    }


def tool_remediate(config_path, **_):
    servers, dropped, errors = _prepare(config_path)
    crit = [c for c in build_chains(servers) if c.severity == "CRITICAL"]
    if not crit:
        return {"config": config_path, "critical_chains": 0, "fix": None,
                "message": "no critical chains — nothing to remediate"}
    rem = minimal_fix(crit)
    return {
        "config": config_path,
        "self_excluded": dropped,
        "critical_chains": len(crit),
        "remove_capabilities": rem.cut,
        "remaining_after_fix": rem.remaining,
        "proven_fix": rem.proven,
    }


def tool_audit(config_path, max=6, driver=None, **_):
    """Full pipeline in one call: scan -> prove -> minimal-fix."""
    servers, dropped, errors = _prepare(config_path)
    chains = build_chains(servers)
    crit = [c for c in chains if c.severity == "CRITICAL"][: int(max)]
    verdicts = [verify_chain(c, servers, driver=driver) for c in crit]
    proven = [v for v in verdicts if v.exploited]
    fix = minimal_fix([v.chain for v in verdicts]) if crit else None
    return {
        "config": config_path,
        "self_excluded": dropped,
        "enumeration_errors": errors,
        "capability_map": _capability_map(servers),
        "critical_chains": len(crit),
        "proven": len(proven),
        "exploitable": len(proven) > 0,
        "findings": [
            _chain_dict(v.chain, exploited=v.exploited,
                        attack_class=v.attack_class, evidence=v.evidence,
                        provenance=v.provenance)
            for v in verdicts
        ],
        "fix": None if not fix else {
            "remove_capabilities": fix.cut,
            "remaining_after_fix": fix.remaining,
            "proven_fix": fix.proven,
        },
    }


# ---------------------------------------------------------------------------
# MCP tool schemas
# ---------------------------------------------------------------------------
_CONFIG_ARG = {
    "config_path": {
        "type": "string",
        "description": "Path to the target agent's MCP config JSON (the mcpServers file).",
    }
}
_MAX_ARG = {"max": {"type": "integer", "description": "Max critical chains to prove (default 6)."}}

TOOLS = {
    "renfield_audit": {
        "fn": tool_audit,
        "description": "One-shot agent pentest: enumerate the target agent's MCP mesh, "
                       "find cross-server confused-deputy exfiltration chains, PROVE each "
                       "by a real side effect (canary egress), and compute the minimal "
                       "config fix. Returns structured findings.",
        "schema": {"type": "object", "properties": {**_CONFIG_ARG, **_MAX_ARG},
                   "required": ["config_path"]},
    },
    "renfield_scan": {
        "fn": tool_scan,
        "description": "Map the target MCP mesh and list CANDIDATE cross-server toxic "
                       "chains (capability analysis only — does not execute).",
        "schema": {"type": "object", "properties": {**_CONFIG_ARG}, "required": ["config_path"]},
    },
    "renfield_verify": {
        "fn": tool_verify,
        "description": "PROVE critical chains by planting a payload and observing a real "
                       "side effect (canary secret reaching an external sink).",
        "schema": {"type": "object", "properties": {**_CONFIG_ARG, **_MAX_ARG},
                   "required": ["config_path"]},
    },
    "renfield_remediate": {
        "fn": tool_remediate,
        "description": "Compute the smallest set of capabilities to remove that breaks "
                       "EVERY critical chain, and confirm 0 remain.",
        "schema": {"type": "object", "properties": {**_CONFIG_ARG}, "required": ["config_path"]},
    },
}


# ---------------------------------------------------------------------------
# minimal JSON-RPC 2.0 stdio server
# ---------------------------------------------------------------------------
def _tools_list():
    return [
        {"name": name, "description": spec["description"], "inputSchema": spec["schema"]}
        for name, spec in TOOLS.items()
    ]


def _call_tool(name, arguments):
    spec = TOOLS.get(name)
    if spec is None:
        raise ValueError(f"unknown tool: {name}")
    result = spec["fn"](**(arguments or {}))
    text = json.dumps(result, indent=2)
    return {"content": [{"type": "text", "text": text}],
            "isError": bool(result.get("error"))}


def _handle(msg):
    """Return a response dict for a request, or None for a notification."""
    method = msg.get("method")
    mid = msg.get("id")

    if method == "initialize":
        return _ok(mid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "renfield", "version": __version__},
        })
    if method in ("notifications/initialized", "initialized"):
        return None  # notification, no reply
    if method == "tools/list":
        return _ok(mid, {"tools": _tools_list()})
    if method == "tools/call":
        params = msg.get("params") or {}
        try:
            return _ok(mid, _call_tool(params.get("name"), params.get("arguments")))
        except Exception as e:  # surface as an MCP tool error, don't crash the server
            return _ok(mid, {"content": [{"type": "text", "text": f"error: {e}"}],
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


def serve(stdin=None, stdout=None) -> int:
    """Run the stdio MCP server loop until stdin closes."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(msg)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
    return 0
