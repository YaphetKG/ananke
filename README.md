# Ananke

Ananke is OpenAI's [Symphony](PLAN.md#2-symphony-distilled-what-we-keep-what-we-change)
orchestration pattern re-purposed for security patching, built on LangChain / LangGraph /
Deep Agents. It polls security findings (Dependabot alerts first, local scanners later),
groups them into work items (one per manifest by default), patches each one in an isolated
sandbox (deterministic bump first, a Deep Agent only when that fails), proves the fix by
running pluggable scanners (Trivy, OSV-Scanner, gitleaks) before and after the change, and
opens a pull request whose body carries that proof of work. [PLAN.md](PLAN.md) is the spec.

## Status

| Milestone | Scope | Status |
|---|---|---|
| M0 | Scaffold, config, Dependabot source, GitHub client, scanner parsers, workflow rendering, triage, `ananke scan` / `scanners` / `validate` | done |
| M1 | One deterministic run end to end (Docker sandbox, fixers, verify, PR body; no LLM) | next |
| M2 | Live agent rung | gated: starts only on the user's explicit go-ahead for a live model |
| M3-M5 | Daemon, operations, reach | planned (PLAN.md §10) |

## Quick start

```bash
uv sync
uv run ananke validate --config ananke.yaml.example
uv run ananke scan --fixtures tests/fixtures --config ananke.yaml.example --all
uv run ananke scanners --config ananke.yaml.example
```

CLI usage:

```
ananke validate --config PATH
ananke scan --config PATH [--fixtures DIR] [--json] [--all]
ananke scanners --config PATH
```

- `validate` checks `ananke.yaml` and the default `ANANKE.md` template, and prints the number
  of configured repos and enabled scanners.
- `scan` fetches open Dependabot alerts and Ananke PRs (`ananke/*` branches) for every
  configured repo, read-only, and prints the triaged work items. It needs GitHub credentials
  (App or `github.token`). With `--fixtures DIR` it reads `DIR/dependabot_alerts/open.json`
  for every repo instead and needs no credentials or network. `--all` also lists findings
  dropped by policy; `--json` prints `{"items": [...], "dropped": [...], "errors": {...}}`.
  An error for one repo is reported and the scan continues; the exit code is then 1.
- `scanners` lists every registered scanner (built-ins and `ananke.scanners` entry points)
  with kinds, ecosystems, whether it is enabled and whether its binary is on this host.

## Configuration

- [`ananke.yaml.example`](ananke.yaml.example): global config (repos, sources, scanners,
  policy, GitHub App, sandbox). Secrets come only from `$VAR` references.
- [`templates/ANANKE.default.md`](templates/ANANKE.default.md): default per-repo workflow
  (front matter + Jinja2 prompt body); a target repo can override it with its own `ANANKE.md`.
- [`docs/SCANNERS.md`](docs/SCANNERS.md): how scanners plug in and the checklist for adding one.

## No live model

Project code and tests never call the Claude API or any other LLM. The only place a chat
model can be constructed is `src/ananke/llm.py`, behind three gates: config
`live_model: true`, env `ANANKE_LIVE_MODEL=1`, and an explicit `--live` flag. Tests use a
scripted fake model (`tests/fixtures/fake_model_scripts/`). See [CLAUDE.md](CLAUDE.md).

## Development

```bash
uv run pytest -q                                   # offline unit tests
uv run ruff check . && uv run ruff format --check .
```

Tests needing Docker, scanner binaries or GitHub/live access are marked `docker`, `binaries`
and `live` and are deselected by default.

## Regenerating scanner fixtures

The scanner outputs under `tests/fixtures/scanner_output/` were written by hand from each
tool's documented JSON schema because the dev host has no scanner binaries. On a machine with
`trivy`, `osv-scanner`, `gitleaks`, `uv` and `npm` on `PATH`, replace them with real tool
output:

```bash
scripts/regen_scanner_fixtures.sh
# fix targets can be overridden, e.g.
PY_REQUESTS_FIX=2.32.4 PY_URLLIB3_FIX=2.5.0 scripts/regen_scanner_fixtures.sh
```

The script copies the fixture repos to a temp dir, scans before and after the fix, and only
moves results into place when every scan succeeded. With the default fix targets, real
scanners will still report some newer advisories in the `after_*` files (for example requests
CVE-2024-47081, fixed in 2.32.4, and urllib3 CVE-2025-50181, fixed in 2.5.0); re-run the unit
tests afterwards and review the diff.
