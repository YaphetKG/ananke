# CLAUDE.md — working in the Ananke repo

Ananke is a Symphony-style security patching agent built on LangChain / LangGraph / Deep Agents.
`PLAN.md` is the spec; read the relevant sections before changing anything.

## Hard rule: no live model

- Never call the Claude API or any LLM from project code or tests.
- The only place a chat model may be constructed is `src/ananke/llm.py`, behind a three-way
  gate: config `live_model: true` AND env `ANANKE_LIVE_MODEL=1` AND an explicit `live=True`
  argument (the CLI `--live` flag). A unit test asserts `ChatAnthropic(` appears nowhere else
  under `src/`.
- Tests use the fake model (`ananke.llm.get_model(cfg, fake_script=...)`, built on
  `GenericFakeChatModel`) with scripts under `tests/fixtures/fake_model_scripts/`.
- Do not exercise the live path unless the user explicitly says "go live" in the session.

## Environment

- Python 3.11+, managed by `uv` (virtualenv in `.venv`). No Docker, no trivy/osv-scanner/
  gitleaks/go on this host (PLAN.md §15). Use `LocalSandbox` (dev/test only, not isolated)
  for tests; production uses `DockerSandbox`.

## Running checks

```bash
uv sync                                   # install
uv run pytest                             # unit tests; docker/binaries/live markers deselected
uv run pytest -m docker                   # needs a Docker daemon
uv run ruff check . && uv run ruff format --check .
uv run ananke validate --config ananke.yaml.example
```

Tests must stay offline and `tests/unit` must run in under 60 s. Mark tests that need Docker
`@pytest.mark.docker`, scanner binaries `@pytest.mark.binaries`, GitHub/live model
`@pytest.mark.live`.

## File ownership (PLAN.md §15)

- Multiple agents work in this tree concurrently. Each agent owns the files its brief names;
  do not edit files owned by another agent's brief.
- Do not edit `pyproject.toml` or `uv.lock` outside the scaffold and integration phases.
  If you need a dependency, report it (package + reason) instead of adding it.
- Do not run `git commit` unless your brief says so.
- `tests/fixtures/` holds recorded tool output and fake-model scripts; treat it as data.

## Conventions

- Stubs for future milestones raise `NotImplementedError` naming the milestone.
- Logging: `from ananke.logging import get_logger; log.info("event_name", item_key=..., run_id=...)`.
- Config: `ananke.config.load_config(path) -> AnankeConfig`; ANANKE.md front matter via
  `ananke.config.parse_repo_workflow(text) -> (RepoWorkflowConfig, body)`.
