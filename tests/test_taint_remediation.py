"""Taint-aware remediation: keep-constrained minimal cut + taint barriers."""

import sys
from dataclasses import dataclass
from pathlib import Path

from renfield.classify import classify_servers
from renfield.graph import build_chains, minimal_fix, taint_barriers
from renfield.live import enumerate_tools
from renfield.models import Server
from renfield.provenance import Provenance
from renfield.taint import TaintFlow, TaintHop

VULN = str(Path(__file__).resolve().parents[1] / "examples" / "vuln_server.py")


def _lab():
    roles = ["inbox", "files", "mailer", "web", "oauth"]
    servers = [Server(r, sys.executable, [VULN], {"TOXI_ROLE": r}) for r in roles]
    enumerate_tools(servers)
    classify_servers(servers)
    return [c for c in build_chains(servers) if c.severity == "CRITICAL"]


def test_default_fix_cuts_shared_source():
    rem = minimal_fix(_lab())
    assert rem.cut == ["inbox.read_message"] and rem.proven


def test_keep_forces_fix_downstream():
    # protect the source -> the fix must land on the shared sensitive read instead
    rem = minimal_fix(_lab(), keep=["inbox.read_message"])
    assert "inbox.read_message" not in rem.cut
    assert rem.cut == ["files.read_file"]
    assert rem.proven                       # still breaks every chain
    assert rem.kept == ["inbox.read_message"]


def test_keeping_every_node_yields_unbreakable():
    crit = _lab()
    # protect source + the sensitive read + every sink node -> nothing left to cut
    nodes = set()
    for c in crit:
        nodes |= {c.source.ref, c.sink.ref}
        if c.sensitive:
            nodes.add(c.sensitive.ref)
    rem = minimal_fix(crit, keep=list(nodes))
    assert rem.cut == []
    assert not rem.proven
    assert rem.unbreakable                  # flagged as gate-behind-approval only


# --- taint barriers from proven laundering flows --------------------------- #
@dataclass
class _Chain:
    _hops: str
    def hops(self):
        return self._hops


@dataclass
class _Verdict:
    exploited: bool
    provenance: object
    chain: object


def _laundered_verdict():
    flow = TaintFlow(hops=[
        TaintHop("inbox.read_message", "source", "output"),
        TaintHop("notes.save_note", "relay", "args"),
        TaintHop("notes.load_note", "relay", "output"),
        TaintHop("mailer.send_email", "sink", "args"),
    ])
    prov = Provenance("inbox.read_message", "files.read_file", "mailer.send_email",
                      True, True, True, True, flow=flow)
    return _Verdict(True, prov, _Chain("inbox.read_message -> mailer.send_email"))


def test_taint_barriers_surface_relay_tools():
    barriers = taint_barriers([_laundered_verdict()])
    assert set(barriers) == {"notes.save_note", "notes.load_note"}


def test_taint_barriers_ignore_unexploited_and_direct():
    # not exploited -> ignored; exploited-but-not-laundered -> no relays
    flow = TaintFlow(hops=[TaintHop("a.src", "source", "output"),
                           TaintHop("b.sink", "sink", "args")])
    prov = Provenance("a.src", None, "b.sink", True, True, True, True, flow=flow)
    direct = _Verdict(True, prov, _Chain("a.src -> b.sink"))
    assert taint_barriers([direct]) == {}
