"""LLM provider backends for the agent-under-test driver.

Each provider runs the full agent loop for one model API given a neutral tool
spec and an `execute(name, args) -> str` callback. The caller (LLMAgent) owns the
callback, so it records the real tool calls + results for the oracle — providers
only decide *which* tools to call.

- OllamaProvider — local models via Ollama HTTP (stdlib only, no API key).
- OpenAIProvider — GPT / Codex, or ANY OpenAI-compatible endpoint via base_url
                   (OpenRouter, Groq, Together, local vLLM) — reaches 100+ models
                   through the official `openai` SDK (extra: [openai]).

API keys come from the standard env var (OPENAI_API_KEY) or an explicit api_key —
never a plaintext key file. The optional SDK is imported lazily so the core
install stays dependency-free.
"""

from __future__ import annotations

import json
from typing import Callable, Protocol

from . import llm

# tool executor: (tool_name, args) -> result text
Execute = Callable[[str, dict], str]

PROVIDER_DEFAULT_MODEL = {
    "ollama": llm.DEFAULT_MODEL,          # qwen2.5:7b
    "openai": "gpt-4o",
}


class ProviderError(RuntimeError):
    pass


class Provider(Protocol):
    def run_agent_loop(
        self, system: str, user_task: str, tools: list[dict],
        execute: Execute, max_steps: int,
    ) -> str | None: ...


def _params(tool: dict) -> dict:
    return tool.get("parameters") or {"type": "object", "properties": {}}


# --------------------------------------------------------------------------- #
# Ollama (local, stdlib HTTP)
# --------------------------------------------------------------------------- #
class OllamaProvider:
    def __init__(self, model: str = llm.DEFAULT_MODEL, host: str | None = None,
                 chat_fn=None):
        self.model = model
        self.host = host or llm.DEFAULT_HOST
        # injectable for tests; defaults to the real Ollama HTTP call
        self.chat_fn = chat_fn or (lambda m, msgs, tls: llm.chat(m, msgs, tls, host=self.host))

    def run_agent_loop(self, system, user_task, tools, execute, max_steps):
        ollama_tools = [llm.tool_def(t["name"], t.get("description", ""), _params(t)) for t in tools]
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user_task}]
        for _ in range(max_steps):
            msg = self.chat_fn(self.model, messages, ollama_tools)
            messages.append(msg)
            calls = msg.get("tool_calls") or []
            if not calls:
                return msg.get("content")
            for call in calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments")
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                result = execute(name, args or {})
                messages.append({"role": "tool", "tool_name": name, "content": result})
        return None


# --------------------------------------------------------------------------- #
# OpenAI / Codex / OpenAI-compatible — official SDK
# --------------------------------------------------------------------------- #
class OpenAIProvider:
    def __init__(self, model: str = "gpt-4o", api_key: str | None = None,
                 base_url: str | None = None):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url  # set for OpenRouter / Groq / Together / local vLLM

    def run_agent_loop(self, system, user_task, tools, execute, max_steps):
        try:
            import openai
        except ImportError as exc:
            raise ProviderError(
                "OpenAI driver needs the OpenAI SDK: pip install 'renfield[openai]' "
                "and set OPENAI_API_KEY (or pass --base-url for a compatible endpoint)."
            ) from exc

        client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)
        oai_tools = [
            {"type": "function",
             "function": {"name": t["name"], "description": t.get("description", ""),
                          "parameters": _params(t)}}
            for t in tools
        ]
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user_task}]
        for _ in range(max_steps):
            resp = client.chat.completions.create(model=self.model, messages=messages, tools=oai_tools)
            msg = resp.choices[0].message
            calls = msg.tool_calls or []
            messages.append({
                "role": "assistant",
                "content": msg.content or "",
                **({"tool_calls": [
                    {"id": c.id, "type": "function",
                     "function": {"name": c.function.name, "arguments": c.function.arguments}}
                    for c in calls]} if calls else {}),
            })
            if not calls:
                return msg.content
            for c in calls:
                try:
                    args = json.loads(c.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                out = execute(c.function.name, args)
                messages.append({"role": "tool", "tool_call_id": c.id, "content": out})
        return None


def build_provider(name: str, model: str | None = None, api_key: str | None = None,
                   base_url: str | None = None, host: str | None = None) -> Provider:
    model = model or PROVIDER_DEFAULT_MODEL.get(name)
    if name == "ollama":
        return OllamaProvider(model, host=host)
    if name == "openai":
        return OpenAIProvider(model, api_key=api_key, base_url=base_url)
    raise ProviderError(f"unknown provider '{name}' (use: ollama | openai)")
