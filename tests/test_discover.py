"""Universal agent-config discovery — works with any MCP-capable agent."""

import json

from renfield import discover


def test_discover_finds_project_mcp_json(tmp_path, monkeypatch):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"x": {"command": "true"}}}))
    monkeypatch.chdir(tmp_path)
    label, path = discover.discover()
    assert path == str(cfg)
    assert "Claude Code" in label


def test_discover_accepts_servers_shape(tmp_path, monkeypatch):
    # VS Code style uses {"servers": {...}} instead of mcpServers
    cfg = tmp_path / ".vscode" / "mcp.json"
    cfg.parent.mkdir()
    cfg.write_text(json.dumps({"servers": {"y": {"command": "true"}}}))
    monkeypatch.chdir(tmp_path)
    label, path = discover.discover()
    assert path == str(cfg)


def test_discover_ignores_empty_block(tmp_path, monkeypatch):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {}}))
    monkeypatch.chdir(tmp_path)
    # nothing else present -> falls through to user paths (which we can't assert),
    # so just assert it doesn't return this empty project file
    label, path = discover.discover()
    assert path != str(tmp_path / ".mcp.json")
