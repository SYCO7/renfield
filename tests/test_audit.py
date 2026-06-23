"""One-shot `audit` command: enumerate once, then scan -> prove -> minimal-fix."""

import json
from pathlib import Path

from renfield.cli import main

CFG = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_lab_config.json")


def test_audit_exit_nonzero_when_chains_proven(capsys):
    # the vulnerable lab has proven cross-server chains -> audit must gate (exit 1)
    rc = main(["audit", CFG])
    assert rc == 1
    out = capsys.readouterr().out
    assert "PROVEN" in out
    assert "minimal fix" in out.lower()


def test_audit_patch_emits_fixed_config(tmp_path):
    out = tmp_path / "fixed.json"
    main(["audit", CFG, "--patch", str(out)])
    block = json.loads(out.read_text())["mcpServers"]
    assert "inbox" not in block                       # offending source removed
    assert "files" in block and "mailer" in block     # the rest kept
