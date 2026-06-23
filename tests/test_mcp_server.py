"""Renfield AS an MCP server: protocol handshake, tools, and self-exclusion."""

import io
import json
from pathlib import Path

from renfield import mcp_server
from renfield.config import load_config

CFG = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_lab_config.json")


def _drive(requests):
    """Feed JSON-RPC lines through serve(), return parsed responses by id."""
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    stdout = io.StringIO()
    mcp_server.serve(stdin=stdin, stdout=stdout)
    out = {}
    for line in stdout.getvalue().splitlines():
        if line.strip():
            m = json.loads(line)
            out[m.get("id")] = m
    return out


def test_initialize_and_tools_list():
    out = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ])
    assert out[1]["result"]["serverInfo"]["name"] == "renfield"
    names = {t["name"] for t in out[2]["result"]["tools"]}
    assert {"renfield_audit", "renfield_scan", "renfield_verify", "renfield_remediate"} <= names


def test_audit_tool_proves_chains():
    out = _drive([
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
         "params": {"name": "renfield_audit", "arguments": {"config_path": CFG}}},
    ])
    payload = json.loads(out[9]["result"]["content"][0]["text"])
    assert payload["exploitable"] is True
    assert payload["proven"] >= 1
    assert payload["fix"]["remove_capabilities"] == ["inbox.read_message"]


def test_self_exclusion_strips_renfield_server(tmp_path):
    cfg = {"mcpServers": {
        "renfield": {"command": "ren", "args": ["serve"]},
        "inbox": {"command": "python3", "args": ["x.py"], "env": {"TOXI_ROLE": "inbox"}},
    }}
    p = tmp_path / "withself.json"
    p.write_text(json.dumps(cfg))
    kept, dropped = mcp_server._strip_self(load_config(str(p)))
    assert [s.name for s in kept] == ["inbox"]
    assert dropped == ["renfield"]


def test_unknown_method_returns_error():
    out = _drive([{"jsonrpc": "2.0", "id": 5, "method": "no/such/method"}])
    assert out[5]["error"]["code"] == -32601
