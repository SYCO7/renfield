"""Tiny Ollama chat client (stdlib only) for the LLM agent driver.

Talks to a local Ollama daemon's /api/chat endpoint with tool/function calling.
No third-party deps — just urllib. If Ollama isn't running, raises OllamaError
with a clear message so the CLI can tell the user to `ollama serve`.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:7b"  # most reliable small-model native tool-calling (2026)


class OllamaError(RuntimeError):
    pass


def chat(model: str, messages: list[dict], tools: list[dict], host: str = DEFAULT_HOST,
         timeout: float | None = None) -> dict:
    """One non-streaming /api/chat turn. Returns the response 'message' dict.

    The per-turn timeout defaults to 120s but is overridable via the
    RENFIELD_OLLAMA_TIMEOUT env var — grammar-constrained tool-calling on CPU can
    be far slower than plain generation, so local users may need to raise it.
    """
    if timeout is None:
        timeout = float(os.environ.get("RENFIELD_OLLAMA_TIMEOUT", "120"))
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
