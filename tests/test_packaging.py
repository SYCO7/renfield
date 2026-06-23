"""Packaging guarantees: the lab ships inside the wheel so `ren quickstart` works
after `pip install` (the examples/ dir is not part of the distribution)."""

from pathlib import Path

import renfield
from renfield.cli import _lab_servers

ROOT = Path(__file__).resolve().parents[1]
PACKAGED = Path(renfield.__file__).resolve().parent / "lab" / "vuln_server.py"
EXAMPLE = ROOT / "examples" / "vuln_server.py"


def test_lab_server_is_bundled_in_the_package():
    assert PACKAGED.is_file(), "vuln_server.py must ship inside renfield/lab/"


def test_packaged_lab_matches_the_examples_copy():
    # anti-drift: the shipped lab and the repo example must stay identical
    assert PACKAGED.read_text() == EXAMPLE.read_text()


def test_lab_servers_resolves_to_the_packaged_copy(monkeypatch, tmp_path):
    # simulate a pip-installed user: cwd has no examples/ dir
    monkeypatch.chdir(tmp_path)
    servers = _lab_servers()
    assert servers is not None and len(servers) == 5
    assert all(str(PACKAGED) in s.args for s in servers)
