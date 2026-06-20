# LinkedIn launch kit

Everything you need to post Renfield. Upload `docs/demo.mp4` as the video.

---

## Post (copy-paste)

> **I built a pentest tool that proves your AI agent will leak your secrets — and ranks which LLMs fall for it.**
>
> Everyone is wiring AI agents to MCP servers (GitHub, filesystem, Slack, email…).
> No single server is "vulnerable" — but their *composition* is.
>
> An attacker who can put text in front of your agent (a GitHub issue, an email, a
> web page) can borrow the agent's own trusted access to read a secret on one server
> and exfiltrate it through another. Classic *confused deputy* — now across MCP
> boundaries. Per-server scanners never see it.
>
> So I built **Renfield**. Point it at your agent's own MCP config and it:
> 🩸 maps the tool mesh and finds the cross-server exfiltration chains
> 🩸 **PROVES** each one by a real side effect — a canary secret physically leaving
>    over the network, or an attacker OAuth consent being granted (not "did the model
>    say something bad")
> 🩸 measures whether YOUR model actually falls for it — and ranks models head-to-head
>
> In the demo it proves 3 attack classes against a deliberately-vulnerable lab, then
> prints a susceptibility leaderboard: one model leaked, another resisted.
>
> Local-first, zero telemetry, MIT, runs free on a local model. SARIF output uploads
> straight to GitHub code scanning so you can gate it in CI.
>
> ⭐ Repo + 60-second demo: github.com/SYCO7/renfield
>
> Built for authorized testing of your own agent stacks. Feedback welcome.
>
> #AISecurity #LLM #PromptInjection #MCP #DevSecOps #RedTeam #CyberSecurity #AIagents

---

## 75-second video script (record your screen running `./demo.sh`, or use docs/demo.mp4)

| Time | On screen | Say |
|------|-----------|-----|
| 0:00–0:08 | Title card / terminal | "AI agents are being wired to MCP servers everywhere. Here's the attack nobody's testing." |
| 0:08–0:20 | `ren scan` output | "I point Renfield at the agent's tool mesh. It tags each tool — untrusted source, sensitive read, external sink — and finds the cross-server chains. Three critical ones here." |
| 0:20–0:45 | `ren verify` output | "Now it PROVES them. Not by grading text — by a real side effect. A canary secret physically leaving over HTTP. An attacker OAuth consent getting approved. Data exfiltrated cross-server. Three attack classes, all confirmed." |
| 0:45–1:05 | `ren compare` leaderboard | "And this is the part nobody could measure before: the same attack across multiple models. One model leaks two ways. Another resists everything. A reproducible susceptibility leaderboard for your stack." |
| 1:05–1:15 | repo page | "Local-first, free on a local model, SARIF for CI. Link's in the post. Test only what you own." |

---

## Where else to post (reach)

- **GitHub topics** already set → discoverable in search.
- **r/netsec**, **r/AIsecurity**, Hacker News "Show HN".
- **OWASP** Slack / the GenAI security community.
- Tag the attack class in posts: "cross-server confused deputy", "lethal trifecta", "indirect prompt injection".
