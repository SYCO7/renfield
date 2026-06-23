import sys
from pathlib import Path

from renfield.live import enumerate_tools
from renfield.models import Server

VULN = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_server.py")


def test_enumerate_inbox_role():
    s = Server(name="inbox", command=sys.executable, args=[VULN], env={"TOXI_ROLE": "inbox"})
    results = enumerate_tools([s])
    assert results[0].ok
    assert {t.name for t in s.tools} == {"read_message"}


def test_enumerate_all_roles():
    s = Server(name="all", command=sys.executable, args=[VULN], env={"TOXI_ROLE": "all"})
    enumerate_tools([s])
    assert {t.name for t in s.tools} == {
        "read_message", "read_file", "send_email", "http_post", "approve_consent",
        "delete_file", "read_api_key", "trigger_deploy", "save_note", "load_note",
    }


def test_enumerate_missing_command_reports_error():
    s = Server(name="nope", command="")
    results = enumerate_tools([s])
    assert not results[0].ok
