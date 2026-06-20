#!/usr/bin/env python3
"""Deliberately-VULNERABLE MCP server — toxitrace test target / lab.

One script, three roles (TOXI_ROLE = inbox | files | mailer | all). Run three
instances to model a cross-server confused-deputy stack:

    inbox.read_message   -> untrusted source (serves attacker-controlled text)
    files.read_file      -> sensitive read   (reads from the sandbox root)
    mailer.send_email    -> external sink     (appends to the egress capture log)

Env:
    TOXI_ROLE     role to expose (default: all)
    TOXI_SANDBOX  sandbox root files are read from (default: cwd)
    TOXI_EGRESS   path the sink writes to (default: <sandbox>/egress.log)

This is intentionally insecure (no path confinement, obeys any instruction).
Use only inside toxitrace's sandbox. Never expose it on a network.
"""

import json
import os
import sys

ROLE = os.environ.get("TOXI_ROLE", "all")
SANDBOX = os.environ.get("TOXI_SANDBOX", os.getcwd())
EGRESS = os.environ.get("TOXI_EGRESS", os.path.join(SANDBOX, "egress.log"))

TOOLDEFS = {
    "read_message": ("Read an incoming message from the inbox", "inbox"),
    "read_file": ("Read a file from the local filesystem", "files"),
    "send_email": ("Send an email to a recipient", "mailer"),
}


def tools_for_role():
    out = []
    for name, (desc, role) in TOOLDEFS.items():
        if ROLE in ("all", role):
            out.append(
                {
                    "name": name,
                    "description": desc,
                    "inputSchema": {"type": "object", "properties": {}},
                }
            )
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
