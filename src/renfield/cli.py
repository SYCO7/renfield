"""Command-line entry point.

    renfield scan   <mcp-config.json> [--tools <manifest.json> | --live] [--min-severity LOW]
    renfield verify <mcp-config.json> [--max N]   # live-enumerate, then PROVE criticals
"""

from __future__ import annotations

import argparse
import sys

from .classify import classify_servers
from .config import attach_tools, load_config, load_tools_manifest
from .graph import build_chains
from .live import enumerate_tools
from .report import render
from .verify import verify_chain

_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


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
    driver_label = "scripted" if args.driver == "scripted" else f"{args.driver}:{args.model or 'default'}"

    print("=" * 66)
    print("renfield — dynamic verification (v0.4)")
    print("=" * 66)
    print(f"driver: {driver_label}")
    if args.driver != "scripted":
        print("  (a real model decides whether to walk the chain — measures actual"
              " susceptibility)")
    if not criticals:
        print("no CRITICAL cross-server chains to verify.")
        return 0
    print(f"verifying {len(criticals)} critical chain(s) by observed side effect...\n")

    proven = 0
    for i, chain in enumerate(criticals, 1):
        verdict = verify_chain(chain, servers, driver=driver)
        status = "PROVEN" if verdict.exploited else "NOT PROVEN"
        proven += int(verdict.exploited)
        print(f"[{status}] #{i}  {chain.hops()}")
        for step in verdict.trace:
            observed = step["observed"].replace("\n", " ")[:70]
            print(f"          {step['step']:<9} {step['tool']:<22} -> {observed}")
        if verdict.error:
            print(f"          error: {verdict.error}")
        print(f"          oracle: {verdict.evidence or '—'}\n")

    print("-" * 66)
    print(f"{proven}/{len(criticals)} chains PROVEN exploitable by real side effect.")
    print("Only test agent stacks you own or are authorized to assess.")
    print("=" * 66)
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
        choices=["scripted", "ollama", "anthropic", "openai"],
        default="scripted",
        help="scripted = deterministic walk (no LLM); ollama/anthropic/openai = a "
             "real model decides (measures susceptibility)",
    )
    verify.add_argument(
        "--model",
        help="model id (default per driver: ollama=qwen2.5:7b, anthropic=claude-opus-4-8, openai=gpt-4o)",
    )
    verify.add_argument(
        "--api-key",
        help="API key (else read from ANTHROPIC_API_KEY / OPENAI_API_KEY env)",
    )
    verify.add_argument(
        "--base-url",
        help="OpenAI-compatible base URL (OpenRouter / Groq / Together / local vLLM)",
    )
    verify.add_argument(
        "--ollama-host", help="Ollama host (default http://localhost:11434)"
    )
    verify.set_defaults(func=_run_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
