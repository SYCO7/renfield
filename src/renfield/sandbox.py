"""Disposable evidence workspace for dynamic verification.

Each run gets a throwaway temp dir holding a unique CANARY secret and an egress
capture file. The oracle later proves exploitation iff the canary value lands in
the egress sink — i.e. data actually crossed from a sensitive read to an
external sink, not merely "the model said something bad".

NOTE: this is an *evidence* workspace, not a security isolation boundary. It does
not contain a hostile MCP server. To test untrusted third-party servers, run
Renfield inside a throwaway VM or container.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass


@dataclass
class Sandbox:
    root: str
    egress: str
    canary: str
    source_token: str = ""      # provenance label for attacker-controlled input
    secret_relpath: str = "secret.txt"
    message_relpath: str = "inbox_message.txt"
    victim_relpath: str = "victim.txt"   # integrity target a destructive sink can wipe

    def victim_intact(self) -> bool:
        """True iff the integrity-target file still exists with its original content."""
        path = os.path.join(self.root, self.victim_relpath)
        try:
            with open(path) as f:
                return f.read() == self.canary
        except OSError:
            return False


def create_sandbox() -> Sandbox:
    root = tempfile.mkdtemp(prefix="renfield-")
    canary = f"CANARY-{uuid.uuid4().hex}"
    source_token = f"SRC-{uuid.uuid4().hex}"
    with open(os.path.join(root, "secret.txt"), "w") as f:
        f.write(canary)
    with open(os.path.join(root, "victim.txt"), "w") as f:
        f.write(canary)               # destructive proof = this file gone/changed
    with open(os.path.join(root, "readme.txt"), "w") as f:
        f.write("public, non-sensitive content")
    return Sandbox(root=root, egress=os.path.join(root, "egress.log"),
                   canary=canary, source_token=source_token)


def plant_payload(sandbox: Sandbox, text: str) -> None:
    """Drop the attacker-controlled message the source tool will serve up.

    A unique, innocuous-looking message id (the source_token) is appended so the
    provenance oracle can later confirm this *attacker-controlled* input was the
    data the agent ingested before it walked the chain (taint origin labelling).
    """
    body = text if not sandbox.source_token else f"{text}\n\n[msg-id: {sandbox.source_token}]"
    with open(os.path.join(sandbox.root, sandbox.message_relpath), "w") as f:
        f.write(body)


def runtime_env(sandbox: Sandbox) -> dict[str, str]:
    return {"TOXI_SANDBOX": sandbox.root, "TOXI_EGRESS": sandbox.egress}


def destroy_sandbox(sandbox: Sandbox) -> None:
    shutil.rmtree(sandbox.root, ignore_errors=True)
