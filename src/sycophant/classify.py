"""Heuristic capability classifier.

v0.1 uses keyword matching over tool name + description. It is intentionally
simple and will produce false positives/negatives — that is fine: the job here
is to surface *candidate* chains for the dynamic engine to later confirm by
observed side effect. Refinement (LLM-assisted tagging, schema inspection) lands
in a later version.
"""

from __future__ import annotations

from .models import Capability, Server, Tool

# Tools that ingest attacker-influenceable / external content.
SOURCE_HINTS = (
    "read_issue", "get_issue", "list_issues", "read_comment", "get_comment",
    "read_email", "get_email", "read_inbox", "read_message", "get_message",
    "fetch", "browse", "web_search", "search_web", "crawl", "read_page",
    "get_page", "read_pr", "get_pr", "read_pull", "pull_request_get",
    "read_review", "read_ticket", "read_webhook", "get_url", "open_url",
    "download", "rss", "read_feed", "read_thread",
)

# Tools that read secrets / private / local-sensitive data.
SENSITIVE_HINTS = (
    "read_file", "get_file", "file_contents", "cat_file", "read_secret",
    "get_secret", "list_secrets", "read_env", "get_env", "dotenv",
    "read_credential", "get_credential", "private", "ssh", "id_rsa",
    "passwd", "password", "read_key", "get_key", "api_key", "token",
    "vault", "read_database", "query_db", "db_query", "dump", "read_config",
)

# Tools that can push data off the host.
SINK_HINTS = (
    "send", "post", "publish", "upload", "push", "tweet", "reply",
    "create_pr", "create_pull", "create_issue", "create_comment",
    "create_gist", "create_release", "http", "request", "webhook",
    "email_send", "send_email", "make_request", "notify", "outbound",
)


def _matches(text: str, hints) -> bool:
    return any(h in text for h in hints)


def classify_tool(tool: Tool) -> set[Capability]:
    """Return the capability tags for a single tool (name + description)."""
    name = tool.name.lower()
    desc = (tool.description or "").lower()
    caps: set[Capability] = set()

    if _matches(name, SOURCE_HINTS) or _matches(desc, SOURCE_HINTS):
        caps.add(Capability.UNTRUSTED_SOURCE)
    if _matches(name, SENSITIVE_HINTS) or _matches(desc, SENSITIVE_HINTS):
        caps.add(Capability.SENSITIVE_READ)
    if _matches(name, SINK_HINTS) or _matches(desc, SINK_HINTS):
        caps.add(Capability.EXTERNAL_SINK)

    if not caps:
        caps.add(Capability.BENIGN)
    return caps


def classify_servers(servers: list[Server]) -> list[Server]:
    """Tag every tool in place and return the servers."""
    for server in servers:
        for tool in server.tools:
            tool.capabilities = classify_tool(tool)
    return servers
