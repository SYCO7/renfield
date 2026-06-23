"""Find an agent's MCP config automatically — work with ANY coding agent.

Every MCP-capable agent stores its server mesh in a JSON file with an
`mcpServers` (or `servers` / `mcp.servers`) block. The path differs per agent.
`discover()` walks the well-known locations for the major agents so the user can
run `ren audit` with no path and we point at whatever agent is installed.

Supported out of the box: Claude Code, Claude Desktop, Cursor, Windsurf, Cline,
Roo Code, Continue, VS Code, Zed, Gemini CLI. Unknown agent? Pass the path
explicitly — any file with an `mcpServers` block works.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# (agent label, path) — project-local first, then per-user. Paths may not exist.
def _candidates():
    home = Path.home()
    cwd = Path.cwd()
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    return [
        # --- project-local (highest priority: the repo you're in) ---
        ("Claude Code (project)", cwd / ".mcp.json"),
        ("Cursor (project)", cwd / ".cursor" / "mcp.json"),
        ("VS Code (project)", cwd / ".vscode" / "mcp.json"),
        ("Zed (project)", cwd / ".zed" / "settings.json"),
        # --- per-user ---
        ("Claude Code (user)", home / ".claude.json"),
        ("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json"),
        ("Claude Desktop", home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
        ("Cursor (user)", home / ".cursor" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("Cline", home / "Documents" / "Cline" / "MCP" / "mcp_settings.json"),
        ("Continue", home / ".continue" / "config.json"),
        ("Gemini CLI", home / ".gemini" / "settings.json"),
        ("Zed (user)", xdg / "zed" / "settings.json"),
    ]


def _has_mcp_block(path: Path) -> bool:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    # accept the common shapes: {mcpServers:{}}, {servers:{}}, {mcp:{servers:{}}}
    if isinstance(data.get("mcpServers"), dict) and data["mcpServers"]:
        return True
    if isinstance(data.get("servers"), dict) and data["servers"]:
        return True
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict) and mcp["servers"]:
        return True
    return False


def discover():
    """Return the first existing agent config that has a non-empty MCP block.

    Returns (label, path_str) or (None, None) if nothing is found.
    """
    for label, path in _candidates():
        if path.is_file() and _has_mcp_block(path):
            return label, str(path)
    return None, None


def discover_all():
    """All existing agent configs with an MCP block — for `ren agents`."""
    seen = set()
    out = []
    for label, path in _candidates():
        rp = str(path)
        if rp in seen:
            continue
        seen.add(rp)
        if path.is_file() and _has_mcp_block(path):
            out.append((label, rp))
    return out
