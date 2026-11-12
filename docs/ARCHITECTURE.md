# Architecture

Ananke has a read-only discovery path and a per-item patch path. GitHub is the source of truth
for findings and pull requests; local state is only an audit aid.

```text
ananke.yaml + repo ANANKE.md
          │
          ▼
Dependabot / local scanner source → policy triage → WorkItem per manifest
                                                     │
                                                     ▼
                 host Git clone → Docker worker container
                                    │
                   scans before → deterministic fixer → scans after
                                    │                           │
                                    └──── verify gate ◀────────┘
                                           │ pass
                                           ▼
                             host push + GitHub PR API
```

M0 provides Pydantic config and workflow models, GitHub App/PAT authentication and read-only REST
calls, Dependabot parsing, scanner plugins and normalized deltas, pure triage, and the `scan`,
`scanners`, and `validate` CLI commands. Scanner parsers consume JSON fixtures and do not require
scanner binaries.

M1 runs one item at a time through a LangGraph `StateGraph` (`worker/graph.py`):

1. `prepare_workspace` clones or resets the checkout and the `ananke/<key>` branch on the host,
   starts the sandbox, loads the repo's `ANANKE.md` (or the default), runs the `after_create` and
   `before_run` hooks and `setup_command` in the sandbox, and scans with every enabled scanner.
2. `deterministic_fix` bumps each vulnerable package to the highest fixed version among the
   item's findings and regenerates the lockfile (pip/uv, npm, Go). It runs no model.
3. `verify` scans again and runs the checks of PLAN.md §5 on the host.
4. On a verify failure, `agent` runs a Deep Agent with the prompt rendered from `ANANKE.md` and
   the deterministic rung's failure output, then `verify` runs again. In M1 the agent needs a
   fake-model script. Without one, the run ends with the deterministic verdict.
5. `open_pr` commits, then either stops (`--dry-run`) or pushes and opens or updates the PR.
6. `report` runs the `after_run` hook, removes the container, and writes the run record and its
   evidence to the SQLite audit store.

The host retains GitHub credentials and owns clone, push, and PR operations. Worker commands have
no token or model key, and the checkout's `.git` is read-only inside the container. PR creation
follows a passing independent verifier; writing requires `--yes`, while `--dry-run` prints the
body. The default container network is disabled. A deployment may attach a host-managed
restricted Docker network for registry access; Ananke does not create or police that network.

The daemon, scheduled reconciliation, HTTP status API, and notifications are later milestones. See
[PLAN.md](../PLAN.md) for their intended behavior and acceptance criteria.
