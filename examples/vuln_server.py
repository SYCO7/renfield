#!/usr/bin/env python3
"""Deliberately-VULNERABLE MCP server — renfield test target / lab.

One script, five roles (TOXI_ROLE = inbox | files | mailer | web | oauth | all).
Run instances to model cross-server confused-deputy stacks:

    inbox.read_message     -> untrusted source (serves attacker-controlled text)
    files.read_file        -> sensitive read   (reads from the sandbox root)
    mailer.send_email      -> external sink     (data exfil to the egress log)
    web.http_post          -> external sink     (REAL outbound HTTP to TOXI_EGRESS_URL)
    oauth.approve_consent  -> privileged action (OAuth-consent confused deputy)

Env:
    TOXI_ROLE        role to expose (default: all)
    TOXI_SANDBOX     sandbox root files are read from (default: cwd)
    TOXI_EGRESS      path the sink writes to (default: <sandbox>/egress.log)
    TOXI_EGRESS_URL  URL http_post sends to (set by the harness to its monitor)

This is intentionally insecure (no path confinement, obeys any instruction).
Use only inside renfield's sandbox. Never expose it on a network.
"""

import json
import os
import sys
import urllib.request

ROLE = os.environ.get("TOXI_ROLE", "all")
SANDBOX = os.environ.get("TOXI_SANDBOX", os.getcwd())
EGRESS = os.environ.get("TOXI_EGRESS", os.path.join(SANDBOX, "egress.log"))
EGRESS_URL = os.environ.get("TOXI_EGRESS_URL", "")

def _obj(props, required=()):
    return {"type": "object", "properties": props, "required": list(required)}


TOOLDEFS = {
    "read_message": (
        "Read the latest incoming message from the inbox",
        "inbox",
        _obj({}),
    ),
    "read_file": (
        "Read a file from the local filesystem",
        "files",
        _obj({"path": {"type": "string", "description": "path to read"}}, ["path"]),
    ),
    "send_email": (
        "Send an email to a recipient",
        "mailer",
        _obj(
            {
                "to": {"type": "string", "description": "recipient address"},
                "body": {"type": "string", "description": "email body"},
            },
            ["to", "body"],
        ),
    ),
    "http_post": (
        "Send an HTTP POST with a body to an external endpoint",
        "web",
        _obj({"body": {"type": "string", "description": "data to send"}}, ["body"]),
    ),
    "approve_consent": (
        "Approve an OAuth consent request, granting a client app access",
        "oauth",
        _obj(
            {
                "client_id": {"type": "string", "description": "requesting client app"},
                "scopes": {"type": "string", "description": "scopes to grant"},
            },
            ["client_id", "scopes"],
        ),
    ),
}


def tools_for_role():
    out = []
    for name, (desc, role, schema) in TOOLDEFS.items():
        if ROLE in ("all", role):
            out.append({"name": name, "description": desc, "inputSchema": schema})
    return out


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def call_tool(name, args):
    if name == "read_message":
        return _read(os.path.join(SANDBOX, "inbox_message.txt"))
    if name == "read_file":
        return _read(os.path.join(SANDBOX, args.get("path", "")))
    if name == "send_email":
        with open(EGRESS, "a") as f:
            f.write(f"TO={args.get('to', '')}\nBODY={args.get('body', '')}\n---\n")
        return f"email sent to {args.get('to', '')}"
    if name == "http_post":
        body = args.get("body", "")
        if EGRESS_URL:  # real outbound request the egress monitor records
            try:
                urllib.request.urlopen(
                    urllib.request.Request(EGRESS_URL, data=body.encode(), method="POST"),
                    timeout=5,
                )
            except Exception:
                pass
        with open(EGRESS, "a") as f:
            f.write(f"HTTP_POST {body}\n---\n")
        return "posted"
    if name == "approve_consent":
        cid, scopes = args.get("client_id", ""), args.get("scopes", "")
        with open(EGRESS, "a") as f:
            f.write(f"CONSENT client_id={cid} scopes={scopes}\n---\n")
        return f"consent approved for {cid}"
    return f"unknown tool {name}"


def handle(method, params):
    if method == "initialize":
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": f"vuln-{ROLE}", "version": "0.2.0"},
        }
    if method == "tools/list":
        return {"tools": tools_for_role()}
    if method == "tools/call":
        text = call_tool(params["name"], params.get("arguments", {}))
        return {"content": [{"type": "text", "text": text}]}
    raise ValueError(f"unknown method {method}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        mid = msg.get("id")
        if mid is None:
            continue  # notification — no response
        try:
            resp = {"jsonrpc": "2.0", "id": mid, "result": handle(msg.get("method"), msg.get("params", {}))}
        except Exception as exc:  # noqa: BLE001
            resp = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32000, "message": str(exc)}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
