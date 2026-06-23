"""Ingest an agent's MCP config + optional tool manifest.

Supports the common config shapes:
  - Cursor / Cline / VS Code (mcpServers):  {"mcpServers": {name: {command, args, env}}}
  - VS Code (servers):                      {"servers": {name: {...}}}

A static config only lists *servers*, not their tools. v0.1 reads tools from a
separate manifest JSON (so the pipeline is testable offline). v0.2 will connect
to each server over MCP and call tools/list to enumerate them live.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Server, Tool


def load_config(path: str | Path) -> list[Server]:
    """Parse an MCP config file into Server objects (without tools)."""
    data = json.loads(Path(path).read_text())
    nested = data.get("mcp") if isinstance(data.get("mcp"), dict) else {}
    block = data.get("mcpServers") or data.get("servers") or nested.get("servers") or {}
    servers: list[Server] = []
    for name, spec in block.items():
        spec = spec or {}
        servers.append(
            Server(
                name=name,
                command=spec.get("command", ""),
                args=list(spec.get("args", []) or []),
                env=dict(spec.get("env", {}) or {}),
            )
        )
    return servers


def load_tools_manifest(path: str | Path) -> dict[str, list[dict]]:
    """Load a {server_name: [{name, description}, ...]} manifest."""
    return json.loads(Path(path).read_text())


def attach_tools(servers: list[Server], manifest: dict[str, list[dict]]) -> list[Server]:
    """Attach tools from a manifest onto the matching servers (in place)."""
    by_name = {s.name: s for s in servers}
    for server_name, tools in manifest.items():
        server = by_name.get(server_name)
        if server is None:
            # tool manifest references a server not in the config — keep it anyway
            server = Server(name=server_name)
            servers.append(server)
            by_name[server_name] = server
        for entry in tools:
            server.tools.append(
                Tool(
                    server=server_name,
                    name=entry["name"],
                    description=entry.get("description", ""),
                )
            )
    return servers
