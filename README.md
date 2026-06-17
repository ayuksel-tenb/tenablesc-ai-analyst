# Tenable SC AI Analyst

An MCP server that turns **Tenable Security Center (Tenable.sc)** into a
vulnerability analyst you can just talk to — ask about exposure, top risks,
remediation, hosts, plugins and feed health in plain language, and the agent
calls the right Security Center analysis for you.

- Read-focused tools over the Tenable.sc REST API (built around `/rest/analysis`).
- **API-key auth** (`x-apikey` header) — no token, no session.
- Side-effecting actions (accept/recast risk, tickets, launch scan) are isolated
  and **off by default** (`SC_ENABLE_WRITES`).
- Never touches Token / SAML / LDAP / User / Role / Director endpoints.

---

## Quickstart

### 1. Install

```bash
git clone https://github.com/ayuksel-tenb/tenablesc-ai-analyst
cd tenablesc-ai-analyst
uv venv && source .venv/bin/activate
uv pip install -e .
```

Needs Python 3.12+. No `uv`? Install it once with
`curl -LsSf https://astral.sh/uv/install.sh | bash` (then open a new terminal), or
skip it entirely and use `python3 -m venv .venv && source .venv/bin/activate` then
`pip install -e .`.

### 2. Configure

```bash
cp .env.example .env
```

Set `SC_HOST`, `SC_ACCESS_KEY`, `SC_SECRET_KEY` in `.env` (generate API keys in
Security Center under **Users → API Keys**). `SC_VERIFY=false` for a self-signed
cert. Leave `SC_ENABLE_WRITES=false` for a read-only analyst.

### 3. Connect it to Claude Code

Run this from the repo folder:

```bash
claude mcp add --transport stdio tenablesc-ai-analyst -- "$(pwd)/.venv/bin/tenablesc-ai-analyst-mcp"
```

No keys to repeat — the server reads the `.env` you set in step 2 (it loads the
project's `.env` even when Claude Code launches it from another directory). Then
`/mcp` should show it **connected**.

> Installed somewhere without the repo's `.env` (e.g. a global/uvx install)? Pass
> the keys explicitly instead: add `--env SC_HOST=… --env SC_ACCESS_KEY=… --env
> SC_SECRET_KEY=…` before `--transport`. (Same server works in OpenCode — put it
> under `mcp` in `opencode.json` with `command: ["…","tenablesc-ai-analyst-mcp"]`.)

### 4. Use

Open Claude Code and just ask:

```
What's my critical and high exposure right now, by severity?
Which 10 hosts have the most vulnerabilities?
What are the top remediations that would clear the most risk?
Show me everything related to CVE-2021-44228 (Log4Shell) in my environment.
Which findings have a known public exploit on repository 1?
Is my plugin feed up to date, and are all scanners online?
Find the plugin for "Apache Log4j" and show its solution.
```

The agent picks the right Security Center analysis (severity/host/plugin/CVE/
remediation summaries, trends, or a raw query) and answers from your live data.

---

## Tools

**Analysis:** `sc_list_vulnerabilities`, `sc_vuln_summary_by_host`,
`sc_vuln_summary_by_plugin`, `sc_vuln_summary_by_severity`, `sc_vuln_summary_by_cve`,
`sc_remediation_summary`, `sc_vuln_trend`, `sc_analysis_query` (raw escape hatch).

**Context:** `sc_list_assets`/`sc_get_asset`, `sc_list_repositories`,
`sc_list_solutions`/`sc_get_solution`, `sc_search_plugins`/`sc_get_plugin`,
`sc_list_queries`/`sc_run_query`, `sc_list_scan_results`/`sc_get_scan_result`,
`sc_feed_status`, `sc_list_scanners`.

**Write (only if `SC_ENABLE_WRITES=true`):** `sc_create_accept_risk_rule`,
`sc_create_recast_risk_rule`, `sc_create_ticket`, `sc_launch_scan` — each makes a
persistent change in Security Center.

Most analysis tools share one filter set (severity, plugin ID, IP, repository,
last-seen, exploit-available, CVE) and page with `start_offset`/`end_offset`.

## Layout

```
src/tenablesc_ai_analyst/
  server.py     # FastMCP server (registers read tools; write tools if enabled)
  client.py     # async httpx wrapper (x-apikey auth, shared error handling)
  schemas.py    # reusable analysis filter model
  config.py     # env settings (SC_HOST/SC_ACCESS_KEY/SC_SECRET_KEY/SC_VERIFY/SC_ENABLE_WRITES)
  tools/read.py
  tools/write.py
```

## License

MIT — see [LICENSE](LICENSE).
