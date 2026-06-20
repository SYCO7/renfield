"""Minimal MCP stdio client (JSON-RPC 2.0, newline-delimited).

Just enough of the Model Context Protocol to launch a server, complete the
initialize handshake, list its tools, and call them. Zero dependencies.

Limitation (v0.2): reads are blocking. A server that never replies will hang;
a real-world timeout/watchdog lands later. Fine for local labs + well-behaved
servers that respond promptly.
"""

from __future__ import annotations

import json
import subprocess

PROTOCOL_VERSION = "2025-06-18"


class MCPError(RuntimeError):
    pass


class MCPStdioClient:
    def __init__(self, command, args=None, env=None, cwd=None):
        self.command = command
        self.args = list(args or [])
        self.env = env
        self.cwd = cwd
        self.proc: subprocess.Popen | None = None
        self._id = 0

    def __enter__(self) -> "MCPStdioClient":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> "MCPStdioClient":
        self.proc = subprocess.Popen(
            [self.command, *self.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=self.env,
            cwd=self.cwd,
        )
        self._initialize()
        return self

    # --- JSON-RPC plumbing -------------------------------------------------
    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send(self, obj: dict) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _read_result(self, expect_id: int):
        assert self.proc and self.proc.stdout
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise MCPError("server closed stdout before responding")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # ignore non-JSON noise
            if msg.get("id") == expect_id:
                if "error" in msg:
                    raise MCPError(str(msg["error"]))
                return msg.get("result")
            # otherwise a notification / unrelated message — skip

    def request(self, method: str, params: dict | None = None):
        rid = self._next_id()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        return self._read_result(rid)

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # --- MCP surface -------------------------------------------------------
    def _initialize(self) -> None:
        self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "toxitrace", "version": "0.2.0"},
            },
        )
        self.notify("notifications/initialized")

    def list_tools(self) -> list[dict]:
        return (self.request("tools/list") or {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self) -> None:
        if not self.proc:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            if self.proc.poll() is None:
                self.proc.terminate()
                self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def call_text(result: dict) -> str:
    """Flatten an MCP tools/call result to its text content."""
    try:
        parts = result.get("content", [])
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text")
    except AttributeError:
        return str(result)
