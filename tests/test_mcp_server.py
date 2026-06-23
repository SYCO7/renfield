"""Renfield-as-an-MCP-server: JSON-RPC handshake, tool list, argv mapping, dispatch."""

from renfield import mcp_server as mcp


def _req(method, rid=1, params=None):
    r = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        r["id"] = rid
    if params is not None:
        r["params"] = params
    return r


def test_initialize_reports_protocol_and_server():
    resp = mcp._handle(_req("initialize"))
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"] == "renfield"
    assert "tools" in resp["result"]["capabilities"]


def test_tools_list_exposes_all_commands():
    resp = mcp._handle(_req("tools/list"))
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {"renfield_scan", "renfield_verify", "renfield_compare",
                     "renfield_remediate", "renfield_quickstart"}
    # every tool carries a JSON Schema the host can render
    for t in resp["result"]["tools"]:
        assert t["inputSchema"]["type"] == "object"


def test_notifications_get_no_response():
    assert mcp._handle(_req("notifications/initialized", rid=None)) is None


def test_unknown_method_is_jsonrpc_error():
    resp = mcp._handle(_req("does/not/exist", rid=7))
    assert resp["error"]["code"] == -32601


def test_argv_mapping_scan_defaults_to_live():
    assert mcp._argv_scan({"config": "c.json"}) == \
        ["scan", "c.json", "--min-severity", "LOW", "--live"]
    # a static manifest suppresses --live
    assert "--live" not in mcp._argv_scan({"config": "c.json", "tools": "m.json"})


def test_argv_mapping_verify_threads_driver_flags():
    argv = mcp._argv_verify({"config": "c.json", "driver": "openai",
                             "model": "gpt-4o", "base_url": "http://gw"})
    assert argv[:3] == ["verify", "c.json", "--max"]
    assert "--driver" in argv and "openai" in argv
    assert "--model" in argv and "gpt-4o" in argv
    assert "--base-url" in argv and "http://gw" in argv


def test_argv_mapping_remediate_patch_path():
    assert mcp._argv_remediate({"config": "c.json"}) == ["remediate", "c.json"]
    assert mcp._argv_remediate({"config": "c.json", "patch": True}) == \
        ["remediate", "c.json", "--patch"]
    assert mcp._argv_remediate({"config": "c.json", "patch": "out.json"}) == \
        ["remediate", "c.json", "--patch", "out.json"]


def test_unknown_tool_call_is_flagged_error():
    resp = mcp._handle(_req("tools/call", rid=3,
                            params={"name": "nope", "arguments": {}}))
    assert resp["result"]["isError"] is True


def test_quickstart_runs_the_bundled_lab_end_to_end():
    # exercises the real in-process CLI path: enumerate -> graph -> prove
    resp = mcp._handle(_req("tools/call", rid=9,
                            params={"name": "renfield_quickstart", "arguments": {}}))
    text = resp["result"]["content"][0]["text"]
    assert resp["result"]["isError"] is False
    assert "PROVEN" in text
    assert "[exit code 1]" in text  # findings present -> exit 1, still not a tool error
