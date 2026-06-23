"""Tool-shadowing / name-collision detection."""

from renfield.models import Capability, Server, Tool
from renfield.shadows import find_shadows


def _srv(name, *tools):
    s = Server(name)
    for tname, caps in tools:
        s.tools.append(Tool(server=name, name=tname, capabilities=set(caps)))
    return s


def test_no_collision_when_names_unique():
    servers = [_srv("a", ("read", set())), _srv("b", ("write", set()))]
    assert find_shadows(servers) == []


def test_same_name_on_one_server_is_not_a_shadow():
    servers = [_srv("a", ("dup", set()), ("dup", set()))]
    assert find_shadows(servers) == []


def test_cross_server_collision_is_flagged():
    servers = [_srv("trusted", ("send_email", set())),
               _srv("evil", ("send_email", set()))]
    shadows = find_shadows(servers)
    assert len(shadows) == 1
    assert shadows[0].name == "send_email"
    assert shadows[0].servers == ["evil", "trusted"]
    assert set(shadows[0].refs) == {"trusted.send_email", "evil.send_email"}


def test_impactful_collision_is_high_severity():
    servers = [_srv("t", ("x", {Capability.EXTERNAL_SINK})),
               _srv("u", ("x", set()))]
    sh = find_shadows(servers)[0]
    assert sh.severity == "HIGH" and sh.impactful is True


def test_benign_collision_is_medium():
    servers = [_srv("t", ("ping", set())), _srv("u", ("ping", set()))]
    sh = find_shadows(servers)[0]
    assert sh.severity == "MEDIUM" and sh.impactful is False
