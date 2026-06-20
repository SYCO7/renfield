"""Live tool enumeration over MCP (replaces the static manifest of v0.1)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .mcp_client import MCPError, MCPStdioClient
from .models import Server, Tool


@dataclass
class EnumResult:
    server: str
    ok: bool
    tool_count: int
    error: str = ""


def enumerate_tools(servers: list[Server]) -> list[EnumResult]:
    """Connect to each server, call tools/list, attach Tool objects in place."""
    results: list[EnumResult] = []
    for server in servers:
        if not server.command:
            results.append(EnumResult(server.name, False, 0, "no launch command"))
            continue
        env = {**os.environ, **server.env}
        try:
            client = MCPStdioClient(server.command, server.args, env=env)
            client.start()
            try:
                for td in client.list_tools():
                    server.tools.append(
                        Tool(
                            server=server.name,
                            name=td.get("name", ""),
                            description=td.get("description", ""),
                        )
                    )
            finally:
                client.close()
            results.append(EnumResult(server.name, True, len(server.tools)))
        except (MCPError, OSError) as exc:
            results.append(EnumResult(server.name, False, 0, str(exc)))
    return results
