"""Expose Renfield itself as an MCP server (stdio transport).

Renfield is normally an MCP *client* — it points at an agent's MCP config and
scans the tool mesh. This module turns it inside-out: it serves Renfield's own
commands (scan / verify / compare / remediate / quickstart) as MCP *tools*, so a
host agent (Claude Desktop, Cursor, etc.) can drive a pentest by calling tools.

Zero extra dependencies — the MCP stdio transport is newline-delimited JSON-RPC
2.0, implemented here against the stdlib only, matching Renfield's no-deps ethos.

Run it directly:

    renfield-mcp          # speaks JSON-RPC on stdin/stdout

Wire it into a host's mcpServers config:

    {"mcpServers": {"renfield": {"command": "renfield-mcp"}}}

SAFETY: verify/compare run REAL confused-deputy exploit proofs against whatever
config they're handed. Only point them at agent stacks you own or are authorized
to assess.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout

from . import __version__
from .cli import main as cli_main

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "renfield", "version": __version__}

# ---- tool registry --------------------------------------------------------
# Each tool maps an MCP call (name + args dict) to a Renfield CLI argv list.

_CONFIG_PROP = {
    "config": {
        "type": "string",
        "description": "Path to the target MCP config JSON (the agent stack to assess).",
    }
}


def _argv_scan(a: dict) -> list[str]:
    argv = ["scan", a["config"], "--min-severity", a.get("min_severity", "LOW")]
    if a.get("tools"):
        argv += ["--tools", a["tools"]]
    elif a.get("live", True):
        argv.append("--live")
    return argv


def _argv_verify(a: dict) -> list[str]:
    argv = ["verify", a["config"], "--max", str(a.get("max", 3)),
            "--driver", a.get("driver", "scripted"),
            "--format", a.get("format", "text")]
    for flag in ("model", "api_key", "base_url", "ollama_host"):
        if a.get(flag):
            argv += ["--" + flag.replace("_", "-"), a[flag]]
    return argv


def _argv_compare(a: dict) -> list[str]:
    argv = ["compare", a["config"], "--max", str(a.get("max", 5))]
    for spec in a.get("with", []) or []:
        argv += ["--with", spec]
    for flag in ("api_key", "base_url", "ollama_host"):
        if a.get(flag):
            argv += ["--" + flag.replace("_", "-"), a[flag]]
    return argv


def _argv_remediate(a: dict) -> list[str]:
    argv = ["remediate", a["config"]]
    if a.get("patch"):
        # a.get("patch") may be True (default outfile) or a path string
        argv.append("--patch")
        if isinstance(a["patch"], str):
            argv.append(a["patch"])
    return argv


def _argv_quickstart(a: dict) -> list[str]:
    return ["quickstart"]


TOOLS = {
    "renfield_scan": {
        "fn": _argv_scan,
        "description": "Enumerate the agent's MCP mesh and report cross-server "
                       "confused-deputy chains (the lethal trifecta). Static map, "
                       "no exploit run. Exit code 1 if a CRITICAL chain exists.",
        "schema": {
            "type": "object",
            "properties": {
                **_CONFIG_PROP,
                "live": {"type": "boolean", "default": True,
                         "description": "Enumerate tools live over MCP (default). "
                                        "Set false to use a static --tools manifest."},
                "tools": {"type": "string",
                          "description": "Path to a {server:[tools]} manifest "
                                         "(static mode; ignored if live)."},
                "min_severity": {"type": "string",
                                 "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                                 "default": "LOW"},
            },
            "required": ["config"],
        },
    },
    "renfield_verify": {
        "fn": _argv_verify,
        "description": "Live-enumerate, then PROVE each CRITICAL chain by an "
                       "observed side effect (canary secret reaching a sink). With "
                       "driver=ollama/openai a REAL model decides whether to walk "
                       "the chain — measures actual injection susceptibility.",
        "schema": {
            "type": "object",
            "properties": {
                **_CONFIG_PROP,
                "max": {"type": "integer", "default": 3,
                        "description": "Max critical chains to verify."},
                "driver": {"type": "string",
                           "enum": ["scripted", "ollama", "openai"],
                           "default": "scripted",
                           "description": "scripted = deterministic walk (no LLM). "
                                          "ollama/openai = a real model decides."},
                "model": {"type": "string",
                          "description": "Model id (ollama=qwen2.5:7b, openai=gpt-4o)."},
                "api_key": {"type": "string",
                            "description": "API key (else OPENAI_API_KEY env)."},
                "base_url": {"type": "string",
                             "description": "OpenAI-compatible base URL (gateways)."},
                "ollama_host": {"type": "string",
                                "description": "Ollama host (default localhost:11434)."},
                "format": {"type": "string",
                           "enum": ["text", "json", "sarif"], "default": "text"},
            },
            "required": ["config"],
        },
    },
    "renfield_compare": {
        "fn": _argv_compare,
        "description": "Run the attack against several models and return a "
                       "susceptibility leaderboard (who walks the chain, which "
                       "attack classes land).",
        "schema": {
            "type": "object",
            "properties": {
                **_CONFIG_PROP,
                "max": {"type": "integer", "default": 5},
                "with": {"type": "array", "items": {"type": "string"},
                         "description": "Models to test, e.g. "
                                        "['scripted','ollama:qwen2.5:7b','openai:gpt-4o']."},
                "api_key": {"type": "string"},
                "base_url": {"type": "string"},
                "ollama_host": {"type": "string"},
            },
            "required": ["config"],
        },
    },
    "renfield_remediate": {
        "fn": _argv_remediate,
        "description": "Compute the smallest set of capabilities to remove that "
                       "breaks EVERY critical chain. With patch=true also emit a "
                       "FIXED MCP config (offending server(s) removed) + a diff.",
        "schema": {
            "type": "object",
            "properties": {
                **_CONFIG_PROP,
                "patch": {"type": ["boolean", "string"], "default": False,
                          "description": "true = write <config>.fixed.json; a string "
                                         "path = write there."},
            },
            "required": ["config"],
        },
    },
    "renfield_quickstart": {
        "fn": _argv_quickstart,
        "description": "Zero-setup demo: run the bundled vulnerable lab end-to-end "
                       "(enumerate -> graph -> prove -> remediate). No config needed.",
        "schema": {"type": "object", "properties": {}},
    },
}


# ---- JSON-RPC plumbing ----------------------------------------------------


def _run_tool(name: str, arguments: dict) -> dict:
    """Invoke a Renfield CLI command in-process, capturing its output."""
    spec = TOOLS.get(name)
    if spec is None:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True}
    out, err = io.StringIO(), io.StringIO()
    try:
        argv = spec["fn"](arguments or {})
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_main(argv)
    except SystemExit as exc:  # argparse bailout
        code = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:  # noqa: BLE001 — surface any failure to the host
        text = out.getvalue() + err.getvalue()
        text += f"\n[renfield-mcp] error: {type(exc).__name__}: {exc}"
        return {"content": [{"type": "text", "text": text}], "isError": True}

    text = out.getvalue()
    stderr = err.getvalue()
    if stderr:
        text += ("\n" if text else "") + stderr
    text += f"\n[exit code {code}]"
    # exit code 1 means "findings present" — a successful run, not a tool error.
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _handle(req: dict) -> dict | None:
    """Dispatch one JSON-RPC request; return a response, or None for notifications."""
    method = req.get("method")
    rid = req.get("id")

    if method == "initialize":
        result = {"protocolVersion": PROTOCOL_VERSION,
                  "capabilities": {"tools": {}},
                  "serverInfo": SERVER_INFO}
    elif method == "tools/list":
        result = {"tools": [
            {"name": n, "description": t["description"], "inputSchema": t["schema"]}
            for n, t in TOOLS.items()
        ]}
    elif method == "tools/call":
        params = req.get("params") or {}
        result = _run_tool(params.get("name", ""), params.get("arguments") or {})
    elif method == "ping":
        result = {}
    elif method is not None and method.startswith("notifications/"):
        return None  # notifications get no response
    else:
        if rid is None:
            return None
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}

    if rid is None:
        return None  # it was a notification
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def serve(stdin=None, stdout=None) -> int:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = _handle(req)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
    return 0


def main() -> int:
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
