#!/usr/bin/env bash
# renfield demo — runs the full pipeline against the bundled vulnerable lab.
# No API key, no GPU, no network egress beyond localhost. Deterministic driver.
cd "$(dirname "$0")" || exit 1
export PYTHONPATH=src

echo "############################################################"
echo "# 1. scan  — map the agent's MCP tool mesh (live enumeration)"
echo "############################################################"
python -m renfield.cli scan examples/vuln_lab_config.json --live --min-severity HIGH

echo
echo "############################################################"
echo "# 2. verify — PROVE each critical chain by a real side effect"
echo "############################################################"
python -m renfield.cli verify examples/vuln_lab_config.json --max 6

echo
echo "############################################################"
echo "# 3. compare — model susceptibility leaderboard"
echo "#    add real models: --with ollama:qwen2.5:7b --with openai:gpt-4o"
echo "############################################################"
python -m renfield.cli compare examples/vuln_lab_config.json --with scripted

# verify/compare exit non-zero when chains are PROVEN (the CI gate). The demo
# itself succeeded, so exit 0.
exit 0
