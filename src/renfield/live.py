"""Live tool enumeration over MCP (replaces the static manifest of v0.1).

Servers are enumerated concurrently — each runs in its own subprocess over its
own stdio pipe and appends to its own Server.tools list, so there is no shared
state to race. On a 5-server mesh this turns 5 sequential handshakes into one
round-trip's worth of wall-clock.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .mcp_client import MCPError, MCPStdioClient
from .models import Server, Tool

#: cap concurrent server subprocesses so a huge config can't fork-bomb the host
MAX_WORKERS = 8


def _enumerate_one(server: Server) -> "EnumResult":
    if not server.command:
        return EnumResult(server.name, False, 0, "no launch command")
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
                        schema=td.get("inputSchema", {}) or {},
                    )
                )
        finally:
            client.close()
        return EnumResult(server.name, True, len(server.tools))
    except (MCPError, OSError) as exc:
        return EnumResult(server.name, False, 0, str(exc))


@dataclass
class EnumResult:
    server: str
    ok: bool
    tool_count: int
    error: str = ""


def enumerate_tools(servers: list[Server]) -> list[EnumResult]:
    """Connect to each server (concurrently), call tools/list, attach Tools in place."""
    if not servers:
        return []
    workers = min(MAX_WORKERS, len(servers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # preserve input order in the returned results
        return list(pool.map(_enumerate_one, servers))
