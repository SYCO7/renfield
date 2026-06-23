"""Render a clean, monochrome text report of the capability graph + chains."""

from __future__ import annotations

from .models import Capability, Server, ToxicChain
from .shadows import find_shadows

_RULE = "=" * 66
_THIN = "-" * 66
_BADGE = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED ]", "LOW": "[LOW ]"}


def render(servers: list[Server], chains: list[ToxicChain], mode: str = "static") -> str:
    out: list[str] = []
    out.append(_RULE)
    out.append(f"renfield — MCP agent capability assessment ({mode} enumeration)")
    out.append(_RULE)

    tools = [t for s in servers for t in s.tools]
    out.append(f"servers: {len(servers)}    tools: {len(tools)}")
    out.append("")

    out.append("CAPABILITY MAP")
    out.append(_THIN)
    if not tools:
        out.append("  no tool data — pass --tools <manifest.json> "
                   "(live MCP enumeration arrives in v0.2)")
    for server in servers:
        out.append(f"  {server.name}")
        for tool in server.tools:
            out.append(f"    - {tool.name:<24} {tool.tag_str()}")
    out.append("")

    crit = sum(1 for c in chains if c.severity == "CRITICAL")
    cross = sum(1 for c in chains if c.cross_server)
    out.append("TOXIC CHAINS")
    out.append(_THIN)
    out.append(f"  {len(chains)} candidate chain(s)  |  "
               f"{crit} critical  |  {cross} cross-server")
    out.append("")

    for i, c in enumerate(chains, 1):
        scope = "CROSS-SERVER" if c.cross_server else "single-server"
        out.append(f"{_BADGE[c.severity]} #{i}  {scope}  servers={'+'.join(c.servers)}")
        out.append(f"        {c.hops()}")
        out.append(f"        {c.rationale}")
        out.append(f"        OWASP: {', '.join(c.owasp)}")
        out.append("")

    shadows = find_shadows(servers)
    if shadows:
        out.append("TOOL SHADOWING (name collisions across servers)")
        out.append(_THIN)
        for sh in shadows:
            out.append(f"{_BADGE[sh.severity]} '{sh.name}' defined by {len(sh.servers)} "
                       f"servers: {', '.join(sh.refs)}")
            out.append("        agent disambiguates by name only — a colliding server can "
                       "intercept calls")
            out.append("        OWASP: MCP Tool Shadowing / Tool-Name Collision")
            out.append("")

    out.append(_THIN)
    out.append("NOTE: `scan` reports *candidate* chains from capability analysis.")
    out.append("      Run `renfield verify` to PROVE a chain by planting a payload")
    out.append("      and observing a real side effect (file read / egress / token "
               "reuse).")
    out.append("      Only assess agent stacks you own or are authorized to test.")
    out.append(_RULE)
    return "\n".join(out)


def render_leaderboard(rows: list[dict]) -> str:
    """Render a head-to-head model-susceptibility leaderboard from `compare`."""
    out = [
        _RULE,
        "renfield — model susceptibility leaderboard",
        _RULE,
        f"{'MODEL':<26} {'PWNED':<7} ATTACK CLASSES PROVEN",
        _THIN,
    ]
    for r in rows:
        label = str(r["label"])[:25]
        if r.get("error"):
            out.append(f"{label:<26} {'err':<7} setup failed: {r['error'][:28]}")
            continue
        score = f"{r['pwned']}/{r['total']}"
        classes = ", ".join(r["classes"]) if r["classes"] else "(resisted all)"
        out.append(f"{label:<26} {score:<7} {classes}")
    out.append(_THIN)
    out.append("Higher PWNED = more susceptible. `scripted` is the deterministic upper")
    out.append("bound (everything reachable if the agent fully obeys the injection).")
    out.append("Only test agent stacks you own or are authorized to assess.")
    out.append(_RULE)
    return "\n".join(out)


def render_technique_matrix(rows: list[dict], techniques: list[str]) -> str:
    """Render a model × injection-technique robustness grid from `compare --matrix`.

    rows: [{label, bypass: set[str], error?}]. A ✓ means the technique bypassed the
    model (proven by side effect on some critical chain); · means it was resisted.
    """
    abbr = [t[:4] for t in techniques]
    head = "  ".join(f"{a:>4}" for a in abbr)
    out = [
        _RULE,
        "renfield — model × injection-technique robustness matrix",
        _RULE,
        f"{'MODEL':<22} {'RESIST':<7} {head}",
        _THIN,
    ]
    for r in rows:
        label = str(r["label"])[:21]
        if r.get("error"):
            out.append(f"{label:<22} {'err':<7} setup failed: {r['error'][:24]}")
            continue
        bypass = set(r["bypass"])
        cells = "  ".join(f"{'✓' if t in bypass else '·':>4}" for t in techniques)
        resisted = len(techniques) - len(bypass & set(techniques))
        out.append(f"{label:<22} {f'{resisted}/{len(techniques)}':<7} {cells}")
    out.append(_THIN)
    out.append("✓ = technique BYPASSED the model (proven side effect)   · = resisted")
    out.append("legend: " + ", ".join(f"{a}={t}" for a, t in zip(abbr, techniques)))
    out.append("Higher RESIST = more robust to indirect prompt injection.")
    out.append(_RULE)
    return "\n".join(out)


def render_remediation(criticals, rem) -> str:
    """Render the minimal-fix result: smallest capability cut + proof it kills all."""
    out = [_RULE, "renfield — minimal fix (proven remediation)", _RULE,
           f"{len(criticals)} CRITICAL chain(s) found.", ""]
    out.append("Smallest set of capabilities to remove or gate to break ALL of them:")
    for ref in rem.cut:
        out.append(f"   - {ref}")
    out.append("")
    if rem.proven:
        out.append(f"Re-analysis after removing them: 0 / {len(criticals)} critical chains remain.")
        out.append("[PROVEN FIX] this single change eliminates every proven attack above.")
    else:
        out.append(f"{len(rem.remaining)} chain(s) still exploitable after the cut:")
        for c in rem.remaining:
            out.append(f"   ! {c.hops()}")
    out.append(_THIN)
    out.append("Apply by removing the tool, narrowing its permission/scope, or gating it")
    out.append("behind human approval once the agent has ingested untrusted content.")
    out.append(_RULE)
    return "\n".join(out)
