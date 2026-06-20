from pathlib import Path

from sycophant.config import attach_tools, load_config, load_tools_manifest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_load_config_parses_servers():
    servers = load_config(EXAMPLES / "sample_claude_config.json")
    names = {s.name for s in servers}
    assert names == {"github", "filesystem", "gmail"}
    gh = next(s for s in servers if s.name == "github")
    assert gh.command == "npx"


def test_attach_tools():
    servers = load_config(EXAMPLES / "sample_claude_config.json")
    attach_tools(servers, load_tools_manifest(EXAMPLES / "sample_tools.json"))
    gh = next(s for s in servers if s.name == "github")
    tool_names = {t.name for t in gh.tools}
    assert "read_issue" in tool_names
    assert all(t.server == "github" for t in gh.tools)
