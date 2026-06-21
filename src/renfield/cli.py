"""Command-line entry point.

    renfield scan   <mcp-config.json> [--tools <manifest.json> | --live] [--min-severity LOW]
    renfield verify <mcp-config.json> [--max N]   # live-enumerate, then PROVE criticals
"""

from __future__ import annotations

import argparse
import sys

from .classify import classify_servers
from .config import attach_tools, load_config, load_tools_manifest
from .graph import build_chains, minimal_fix, servers_in_cut
from .live import enumerate_tools
from .report import render, render_leaderboard, render_remediation
from .verify import verify_chain

_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def _safe(s) -> str:
    """Strip terminal control chars from server-controlled text (anti-spoofing).

    A malicious MCP server could emit ANSI escapes / control codes in its tool
    output or tool names to forge a clean-looking report. Drop anything that
    isn't printable before we print it.
    """
    return "".join(c for c in str(s) if c.isprintable() or c == " ")


def _prepare(config, tools, live):
    servers = load_config(config)
    if live:
        for r in enumerate_tools(servers):
            if not r.ok:
                print(f"  ! {r.server}: enumeration failed ({r.error})", file=sys.stderr)
    elif tools:
        attach_tools(servers, load_tools_manifest(tools))
    classify_servers(servers)
    return servers


def _run_scan(args: argparse.Namespace) -> int:
    servers = _prepare(args.config, args.tools, args.live)
    chains = build_chains(servers)
    floor = _SEVERITY_RANK[args.min_severity]
    chains = [c for c in chains if _SEVERITY_RANK[c.severity] >= floor]
    print(render(servers, chains, mode="live" if args.live else "static"))
    return 1 if any(c.severity == "CRITICAL" for c in chains) else 0


def _make_driver(args):
    if args.driver == "scripted":
        return None  # default: deterministic ScriptedAgent
    from .agent import LLMAgent
    from .providers import build_provider
    provider = build_provider(
        args.driver, model=args.model, api_key=args.api_key,
        base_url=args.base_url, host=args.ollama_host,
    )
    return LLMAgent(provider=provider)


def _run_verify(args: argparse.Namespace) -> int:
    servers = _prepare(args.config, None, live=True)
    criticals = [c for c in build_chains(servers) if c.severity == "CRITICAL"][: args.max]
    driver = _make_driver(args)
    verdicts = [verify_chain(c, servers, driver=driver) for c in criticals]
    proven = sum(1 for v in verdicts if v.exploited)

    # machine-readable output for CI / GitHub code scanning
    if args.format in ("json", "sarif"):
        from .outputs import render as render_out
        text = render_out(verdicts, args.config, args.format)
        if args.out:
            with open(args.out, "w") as f:
                f.write(text)
            print(f"wrote {args.format} ({proven} finding(s)) -> {args.out}", file=sys.stderr)
        else:
            print(text)
        return 1 if proven else 0

    # human-readable text
    driver_label = "scripted" if args.driver == "scripted" else f"{args.driver}:{args.model or 'default'}"
    print("=" * 66)
    print("renfield — dynamic verification (v0.6)")
    print("=" * 66)
    print(f"driver: {driver_label}")
    if args.driver != "scripted":
        print("  (a real model decides whether to walk the chain — measures actual"
              " susceptibility)")
    if not criticals:
        print("no CRITICAL cross-server chains to verify.")
        return 0
    print(f"verifying {len(criticals)} critical chain(s) by observed side effect...\n")

    for i, verdict in enumerate(verdicts, 1):
        status = "PROVEN" if verdict.exploited else "NOT PROVEN"
        klass = f"  [{verdict.attack_class}]" if verdict.exploited else ""
        print(f"[{status}] #{i}{klass}  {_safe(verdict.chain.hops())}")
        for step in verdict.trace:
            observed = _safe(step["observed"]).replace("\n", " ")[:70]
            print(f"          {_safe(step['step']):<9} {_safe(step['tool']):<22} -> {observed}")
        if verdict.error:
            print(f"          error: {_safe(verdict.error)}")
        print(f"          oracle: {_safe(verdict.evidence) or '—'}\n")

    print("-" * 66)
    print(f"{proven}/{len(criticals)} chains PROVEN exploitable by real side effect.")
    print("Only test agent stacks you own or are authorized to assess.")
    print("=" * 66)
    return 1 if proven else 0


def _spec_driver(spec, args):
    """'scripted' | 'ollama:qwen2.5:7b' | 'openai:gpt-4o' -> a driver instance."""
    if spec == "scripted":
        return None
    driver_name, _, model = spec.partition(":")
    from .agent import LLMAgent
    from .providers import build_provider
    provider = build_provider(
        driver_name, model=model or None, api_key=args.api_key,
        base_url=args.base_url, host=args.ollama_host,
    )
    return LLMAgent(provider=provider)


def _run_compare(args: argparse.Namespace) -> int:
    servers = _prepare(args.config, None, live=True)
    criticals = [c for c in build_chains(servers) if c.severity == "CRITICAL"][: args.max]
    specs = args.with_ or ["scripted"]
    if not criticals:
        print("no CRITICAL cross-server chains to compare.")
        return 0

    rows = []
    for spec in specs:
        try:
            driver = _spec_driver(spec, args)
        except Exception as exc:  # provider/SDK/setup error — record, keep going
            rows.append({"label": spec, "total": len(criticals), "pwned": 0,
                         "classes": [], "error": str(exc)})
            continue
        classes = []
        for chain in criticals:
            verdict = verify_chain(chain, servers, driver=driver)
            if verdict.exploited:
                classes.append(verdict.attack_class)
        rows.append({"label": spec, "total": len(criticals), "pwned": len(classes),
                     "classes": sorted(set(classes))})
    print(render_leaderboard(rows))
    return 1 if any(r["pwned"] for r in rows) else 0


def _emit_patch(config_path: str, cut: list[str], out_arg: str) -> None:
    """Write a fixed MCP config with the offending server(s) removed, and show a diff."""
    import copy
    import difflib
    import json
    from pathlib import Path

    raw = json.loads(Path(config_path).read_text())
    key = "mcpServers" if "mcpServers" in raw else "servers"
    remove = servers_in_cut(cut)
    patched = copy.deepcopy(raw)
    for s in remove:
        patched.get(key, {}).pop(s, None)

    before = json.dumps(raw, indent=2).splitlines(keepends=True)
    after = json.dumps(patched, indent=2).splitlines(keepends=True)
    diff = "".join(difflib.unified_diff(before, after, fromfile="before", tofile="after"))

    print(f"\nFIXED CONFIG — remove server(s): {', '.join(remove)}\n")
    print(diff)
    out = out_arg if out_arg != "-" else str(Path(config_path).with_suffix(".fixed.json"))
    Path(out).write_text(json.dumps(patched, indent=2) + "\n")
    print(f"wrote patched config -> {out}  (re-scan it to confirm 0 critical chains)")


def _run_remediate(args: argparse.Namespace) -> int:
    servers = _prepare(args.config, None, live=True)
    criticals = [c for c in build_chains(servers) if c.severity == "CRITICAL"]
    if not criticals:
        print("no CRITICAL chains — nothing to remediate.")
        return 0
    rem = minimal_fix(criticals)
    print(render_remediation(criticals, rem))
    if getattr(args, "patch", None) is not None:
        _emit_patch(args.config, rem.cut, args.patch)
    return 0


def _lab_servers():
    """Build the bundled vulnerable-lab servers with absolute paths (cwd-independent)."""
    import sys as _sys
    from pathlib import Path

    from .models import Server
    here = Path(__file__).resolve()
    for vuln in (here.parents[2] / "examples" / "vuln_server.py",
                 Path.cwd() / "examples" / "vuln_server.py"):
        if vuln.exists():
            roles = ["inbox", "files", "mailer", "web", "oauth"]
            return [Server(r, _sys.executable, [str(vuln)], {"TOXI_ROLE": r}) for r in roles]
    return None


def _run_quickstart(args: argparse.Namespace) -> int:
    from .verify import verify_chain
    servers = _lab_servers()
    if servers is None:
        print("Couldn't find the bundled lab. Clone the repo and run from its root:\n"
              "  git clone https://github.com/SYCO7/renfield && cd renfield\n"
              "  pip install -e . && ren quickstart")
        return 1

    print("Renfield quickstart — running the bundled vulnerable lab. Zero setup.\n")
    enumerate_tools(servers)
    classify_servers(servers)
    chains = build_chains(servers)
    criticals = [c for c in chains if c.severity == "CRITICAL"]

    print(render(servers, [c for c in chains if c.severity == "CRITICAL"], mode="live"))
    print("\nPROVING each critical chain by a real side effect...\n")
    proven = 0
    for i, chain in enumerate(criticals, 1):
        v = verify_chain(chain, servers)
        proven += int(v.exploited)
        tag = f"[PROVEN] [{v.attack_class}]" if v.exploited else "[NOT PROVEN]"
        print(f"  {tag}  {_safe(chain.hops())}")
    print(f"\n  {proven}/{len(criticals)} chains PROVEN by real side effect.\n")

    print(render_remediation(criticals, minimal_fix(criticals)))
    print("\nNext: point it at YOUR agent —  ren verify path/to/your-mcp-config.json")
    print("Only test agent stacks you own or are authorized to assess.")
    return 1 if proven else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="renfield",
        description="Find and prove cross-server confused-deputy exfiltration "
                    "chains in an AI agent's MCP tool mesh.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="static/live capability scan")
    scan.add_argument("config", help="path to the MCP config JSON")
    src = scan.add_mutually_exclusive_group()
    src.add_argument("--tools", help="path to a {server: [tools]} manifest JSON")
    src.add_argument("--live", action="store_true", help="enumerate tools live over MCP")
    scan.add_argument("--min-severity", choices=list(_SEVERITY_RANK), default="LOW")
    scan.set_defaults(func=_run_scan)

    verify = sub.add_parser("verify", help="live-enumerate, then PROVE critical chains")
    verify.add_argument("config", help="path to the MCP config JSON")
    verify.add_argument("--max", type=int, default=3, help="max chains to verify")
    verify.add_argument(
        "--driver",
        choices=["scripted", "ollama", "openai"],
        default="scripted",
        help="scripted = deterministic walk (no LLM); ollama/openai = a real model "
             "decides (measures susceptibility). openai + --base-url hits any "
             "OpenAI-compatible gateway.",
    )
    verify.add_argument(
        "--model",
        help="model id (default per driver: ollama=qwen2.5:7b, openai=gpt-4o)",
    )
    verify.add_argument(
        "--api-key",
        help="API key (else read from OPENAI_API_KEY env)",
    )
    verify.add_argument(
        "--base-url",
        help="OpenAI-compatible base URL (OpenRouter / Groq / Together / local vLLM)",
    )
    verify.add_argument(
        "--ollama-host", help="Ollama host (default http://localhost:11434)"
    )
    verify.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text",
        help="output format. sarif uploads to GitHub code scanning; json for CI",
    )
    verify.add_argument("-o", "--out", help="write json/sarif to this file")
    verify.set_defaults(func=_run_verify)

    cmp = sub.add_parser(
        "compare",
        help="run the attack against several models and print a susceptibility leaderboard",
    )
    cmp.add_argument("config", help="path to the MCP config JSON")
    cmp.add_argument("--max", type=int, default=5, help="max critical chains to test")
    cmp.add_argument(
        "--with", dest="with_", action="append", metavar="SPEC",
        help="model to test, repeatable. SPEC = 'scripted' | 'ollama:<model>' | "
             "'openai:<model>'. e.g. --with ollama:qwen2.5:7b --with openai:gpt-4o",
    )
    cmp.add_argument("--api-key", help="API key (else OPENAI_API_KEY env)")
    cmp.add_argument("--base-url", help="OpenAI-compatible base URL (gateways)")
    cmp.add_argument("--ollama-host", help="Ollama host (default http://localhost:11434)")
    cmp.set_defaults(func=_run_compare)

    rem = sub.add_parser(
        "remediate",
        help="compute the smallest set of capabilities to remove that breaks EVERY "
             "critical chain, and prove 0 remain",
    )
    rem.add_argument("config", help="path to the MCP config JSON")
    rem.add_argument(
        "--patch", nargs="?", const="-", metavar="OUTFILE",
        help="also emit a FIXED MCP config (offending server(s) removed) + a diff; "
             "pass a path, or omit for <config>.fixed.json",
    )
    rem.set_defaults(func=_run_remediate)

    qs = sub.add_parser(
        "quickstart",
        help="zero-setup demo: run the bundled vulnerable lab end-to-end",
    )
    qs.set_defaults(func=_run_quickstart)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
