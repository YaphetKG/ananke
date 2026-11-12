# Ananke trust and approval posture

Ananke runs untrusted repository code to install dependencies and execute tests. Its safety
boundary is the per-run Docker container and the host-side verification gate. A pull request is
still reviewed and merged by a person; Ananke never merges it.

## Credentials and GitHub writes

- GitHub App or PAT credentials stay in the host process. The host uses a short-lived token to
  clone, fetch, push, and call the GitHub API after verification.
- Git authentication is supplied to host `git` through process environment configuration for the
  duration of a single command. It is not written to `.git/config`, the workspace, command output,
  the container environment, or agent tools.
- The container receives only its workspace bind mount and, when configured, a read-only scanner
  database mount. It never receives the GitHub token, App private key, or model API key.
- The GitHub App should have only the permissions in PLAN.md §11. It must not receive Workflows
  permission. The worker cannot change CI workflow files because those paths are protected by the
  verifier and the App lacks that permission.
- `ananke run` requires `--yes` before pushing a branch and creating/updating a PR. `--dry-run`
  runs the patch and verification path, then prints the proposed PR body without GitHub writes.

## Sandbox

`DockerSandbox` runs one container per work item with dropped Linux capabilities,
`no-new-privileges`, CPU and memory limits, a process limit, a read/write mount for that item's
workspace, and a `/tmp` tmpfs that holds `HOME` and the uv/npm/Go caches. The container runs as
the host user's uid and gid (never root), so files it writes in the workspace stay owned by the
host user. The container has no Docker socket and no host credentials. A configured scanner
database volume is mounted read-only. Raw scanner reports are kept outside the workspace so secret
matches cannot enter a PR diff.

The workspace's `.git` directory is mounted read-only inside the container. Code running there
(dependency installs, tests, agent commands) can change working-tree files but cannot plant git
hooks, `core.fsmonitor`, or other git config. The host's own git commands (`commit`, `push`, and
the verify gate's `diff`) additionally run with hooks and fsmonitor disabled, and the verify gate
never asks the container for git output. Build and test artifacts (`__pycache__`, `.venv`,
`node_modules`, and similar) are listed in the clone's `.git/info/exclude`, so they are neither
reported as changes nor committed.

The default Docker network is `none`. To allow dependency downloads, configure `sandbox.network`
to a Docker network whose host firewall or egress proxy permits only the names in
`sandbox.network_allowlist`. Docker's standard bridge network does not enforce hostname
allowlists; do not use it for worker containers. Ananke passes the configured Docker network name
to `docker run` and does not create or secure that network itself. If a restricted network is not
available, keep `network: none`; package installation may then fail closed.

`bridge`, `host`, and `container:*` networks are refused unless
`sandbox.allow_unrestricted_network: true` is set. That switch exists for the Docker integration
test and must not be used for real repositories.

`sandbox.allow_local: true` enables `LocalSandbox` for development only. It executes commands on
the host without isolation. Local mode strips common secret-bearing environment variable names,
but it is not a security boundary and must not be used for untrusted repositories or production
runs.

## Agent and verification

M0 and M1 make no live model calls. M1 can use only a fake-model script passed with
`--fake-model`; there is no live-agent CLI switch in this milestone. Without a script the agent
rung does not run, and the item ends with the deterministic rung's verdict. The future live path must pass the independent gates in
`ananke.llm` (config, environment, and CLI) and requires a separate explicit user go-ahead.

The agent cannot push or open PRs. A deterministic verifier checks the diff paths and size,
target advisories, new high-severity findings, new secrets, tests, lockfile consistency, and test
tampering. Scanner evidence is generated independently before and after the patch. Any failed
check prevents PR creation.

Repository files, advisory text, release notes, and command output are untrusted data. The default
workflow tells the agent to treat them as data, and verification enforces the path and scan rules
regardless of the agent's report.
