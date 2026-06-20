from sycophant.classify import classify_tool
from sycophant.models import Capability, Tool


def cap(name, desc=""):
    return classify_tool(Tool(server="s", name=name, description=desc))


def test_untrusted_source():
    assert Capability.UNTRUSTED_SOURCE in cap("read_issue")
    assert Capability.UNTRUSTED_SOURCE in cap("fetch_url", "fetch a web page")


def test_sensitive_read():
    assert Capability.SENSITIVE_READ in cap("read_file")
    assert Capability.SENSITIVE_READ in cap("get_file_contents")


def test_external_sink():
    assert Capability.EXTERNAL_SINK in cap("send_email")
    assert Capability.EXTERNAL_SINK in cap("create_pr")


def test_create_issue_is_sink_not_source():
    caps = cap("create_issue")
    assert Capability.EXTERNAL_SINK in caps
    assert Capability.UNTRUSTED_SOURCE not in caps


def test_benign():
    assert cap("list_directory") == {Capability.BENIGN}
