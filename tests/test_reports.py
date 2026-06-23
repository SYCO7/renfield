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


def test_html_report_includes_trace_and_taint():
    html = render(_verdicts(), "cfg", "html")
    assert "tool-call trace" in html          # the LLM/scripted trace UI
    assert "taint:" in html                    # provenance taint path rendered


def test_leaderboard_and_matrix_html():
    from renfield.outputs import leaderboard_to_html, matrix_to_html
    lb = leaderboard_to_html([
        {"label": "scripted", "total": 3, "pwned": 3, "classes": ["Data Exfiltration"]},
        {"label": "tough", "total": 3, "pwned": 0, "classes": []},
        {"label": "broken", "total": 3, "pwned": 0, "classes": [], "error": "no key"},
    ])
    assert lb.startswith("<!doctype html>") and "<script" not in lb.lower()
    assert "3/3" in lb and "resisted all" in lb and "setup failed" in lb

    mx = matrix_to_html(
        [{"label": "m", "bypass": {"direct"}}], ["direct", "authority"])
    assert "robustness" in mx and "1/2" in mx and "✓" in mx


def test_audit_html_via_cli(tmp_path):
    from renfield.cli import main
    out = tmp_path / "audit.html"
    cfg = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_lab_config.json")
    rc = main(["audit", cfg, "--format", "html", "-o", str(out)])
    assert rc == 1                              # chains proven -> gate
    html = out.read_text()
    assert html.startswith("<!doctype html>")
    assert "PROVEN" in html and "tool-call trace" in html


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
