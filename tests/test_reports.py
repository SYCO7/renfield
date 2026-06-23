"""HTML evidence report + model × technique matrix renderer."""

import sys
from pathlib import Path

from renfield.classify import classify_servers
from renfield.graph import build_chains
from renfield.live import enumerate_tools
from renfield.models import Server
from renfield.outputs import render, verdicts_to_html
from renfield.report import render_technique_matrix
from renfield.verify import verify_chain

VULN = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_server.py")


def _verdicts():
    roles = ["inbox", "files", "mailer", "web", "oauth"]
    servers = [Server(r, sys.executable, [VULN], {"TOXI_ROLE": r}) for r in roles]
    enumerate_tools(servers)
    classify_servers(servers)
    crit = [c for c in build_chains(servers) if c.severity == "CRITICAL"][:2]
    return [verify_chain(c, servers) for c in crit]


def test_html_report_is_self_contained_and_escaped():
    html = render(_verdicts(), "examples/vuln_lab_config.json", "html")
    assert html.startswith("<!doctype html>")
    assert "<script" not in html.lower()           # no external/JS dependencies
    assert "PROVEN" in html
    assert "renfield" in html.lower()
    # config path is HTML-escaped via _esc (no raw angle brackets injected)
    assert "<style>" in html


def test_html_escapes_untrusted_text():
    # craft a verdict-like object whose fields contain HTML metacharacters
    vs = _verdicts()
    vs[0].evidence = "<img src=x onerror=alert(1)>"
    html = verdicts_to_html(vs, "cfg")
    assert "<img src=x" not in html
    assert "&lt;img" in html


def test_technique_matrix_grid():
    techs = ["direct", "authority", "obfuscation"]
    rows = [
        {"label": "scripted", "bypass": set(techs)},
        {"label": "tough-model", "bypass": {"obfuscation"}},
        {"label": "broken", "bypass": set(), "error": "no api key"},
    ]
    out = render_technique_matrix(rows, techs)
    assert "robustness matrix" in out
    assert "0/3" in out and "2/3" in out         # scripted bypassed all; tough resisted 2
    assert "setup failed" in out                  # error row rendered
