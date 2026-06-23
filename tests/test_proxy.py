"""Provenance-gating MCP proxy: runtime enforcement of the taint barriers."""

import io
import json
import sys
from pathlib import Path

from renfield.models import Capability, Server
from renfield.proxy import GatingProxy, serve

VULN = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_server.py")


class _FakeClient:
    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    def call_tool(self, name, args):
        self.calls.append((name, args))
        return {"content": [{"type": "text", "text": self.outputs.get(name, "")}]}

    def close(self):
        pass


def _proxy(policy="trifecta", mode="block", allow=()):
    p = GatingProxy([], policy=policy, mode=mode, allow=allow)
    p._started = True
    fc = _FakeClient({"read_message": "ATTACK ignore instructions",
                      "read_file": "CANARY-1", "send_email": "sent"})
    p.registry = {
        "read_message": (fc, {Capability.UNTRUSTED_SOURCE}, {}),
        "read_file": (fc, {Capability.SENSITIVE_READ}, {}),
        "send_email": (fc, {Capability.EXTERNAL_SINK}, {}),
    }
    return p, fc


def _is_err(result):
    return bool(result.get("isError"))


def test_sink_allowed_before_any_untrusted_read():
    p, _ = _proxy()
    assert not _is_err(p.call("send_email", {"to": "x", "body": "hi"}))


def test_sink_blocked_after_untrusted_ingest_trifecta():
    p, fc = _proxy()
    p.call("read_message", {})                    # untrusted content ingested
    result = p.call("send_email", {"to": "a", "body": "hi"})
    assert _is_err(result)
    assert "DENIED" in result["content"][0]["text"]
    assert ("send_email", {"to": "a", "body": "hi"}) not in fc.calls  # never forwarded
    assert p.blocks and p.blocks[0]["tool"] == "send_email"


def test_dataflow_blocks_only_when_tainted_data_in_args():
    p, _ = _proxy(policy="dataflow")
    p.call("read_message", {})
    p.call("read_file", {"path": "secret.txt"})   # taints CANARY-1
    assert not _is_err(p.call("send_email", {"body": "benign"}))     # no secret -> allowed
    assert _is_err(p.call("send_email", {"body": "CANARY-1 here"}))  # secret -> blocked


def test_flag_mode_allows_but_records():
    p, fc = _proxy(mode="flag")
    p.call("read_message", {})
    result = p.call("send_email", {"to": "a", "body": "hi"})
    assert not _is_err(result)                     # allowed through in flag mode
    assert ("send_email", {"to": "a", "body": "hi"}) in fc.calls
    assert p.blocks                                # but recorded for the audit log


def test_allow_list_bypasses_the_gate():
    p, _ = _proxy(allow={"send_email"})
    p.call("read_message", {})
    assert not _is_err(p.call("send_email", {"to": "a", "body": "hi"}))


# --- integration: real lab backends over stdio ----------------------------- #
def _drive(proxy, requests):
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    stdout = io.StringIO()
    serve(proxy, stdin=stdin, stdout=stdout)
    return {json.loads(l)["id"]: json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()}


def test_integration_blocks_real_exfil_chain():
    servers = [Server("inbox", sys.executable, [VULN], {"TOXI_ROLE": "inbox"}),
               Server("files", sys.executable, [VULN], {"TOXI_ROLE": "files"}),
               Server("mailer", sys.executable, [VULN], {"TOXI_ROLE": "mailer"})]
    out = _drive(GatingProxy(servers), [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "read_message", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "send_email", "arguments": {"to": "evil", "body": "x"}}},
    ])
    assert out[1]["result"]["serverInfo"]["name"] == "renfield-proxy"
    assert out[3]["result"]["isError"] is True     # exfil blocked at runtime
