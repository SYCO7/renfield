"""Tiny Ollama chat client (stdlib only) for the LLM agent driver.

Talks to a local Ollama daemon's /api/chat endpoint with tool/function calling.
No third-party deps — just urllib. If Ollama isn't running, raises OllamaError
with a clear message so the CLI can tell the user to `ollama serve`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:7b"  # most reliable small-model native tool-calling (2026)


class OllamaError(RuntimeError):
    pass


def chat(model: str, messages: list[dict], tools: list[dict], host: str = DEFAULT_HOST,
         timeout: float = 120.0) -> dict:
    """One non-streaming /api/chat turn. Returns the response 'message' dict."""
    payload = json.dumps(
        {"model": model, "messages": messages, "tools": tools, "stream": False}
    ).encode()
    req = urllib.request.Request(
        f"{host}/api/chat", data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
    except urllib.error.URLError as exc:
        raise OllamaError(
            f"cannot reach Ollama at {host} ({exc}). Is it running? "
            f"Try: `ollama serve` and `ollama pull {model}`."
        ) from exc
    if "error" in body:
        raise OllamaError(str(body["error"]))
    return body.get("message", {})


def tool_def(name: str, description: str, schema: dict) -> dict:
    """Build an Ollama function-tool definition from an MCP tool."""
    params = schema or {"type": "object", "properties": {}}
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": params},
    }
