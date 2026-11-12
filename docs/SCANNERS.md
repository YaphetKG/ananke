# Scanners

Scanners are local tools that run **inside the sandbox** against a workspace (PLAN.md §3.5).
They *discover* findings, and they *attest*: the same scanner runs before and after a change,
and the normalized delta (`ananke.scanners.base.delta`) is the proof of work that the verify
node and the PR body consume. No scanner-specific logic leaks past the scanner's own module:
everything downstream sees only `ScanFinding`, `ScanReport`, `ScanDelta` and `ScannerVersion`.

Built-in scanners: `trivy` (`src/ananke/scanners/trivy.py`), `osv`
(`src/ananke/scanners/osv.py`), `gitleaks` (`src/ananke/scanners/gitleaks.py`).

## Adding a scanner: the checklist

Adding a scanner is one module, one fixture, one registry line, one install line, and
(optionally) an options block. Nothing else in Ananke changes.

1. **One module** implementing the `Scanner` protocol from `ananke.scanners.base`:

   ```python
   class MyScanner:
       name = "mytool"  # key in scanners.enabled
       kinds = frozenset({"dependency"})  # dependency|container|iac|secret|sast
       ecosystems = frozenset({"pip", "npm"})  # or {"*"}

       def __init__(self, options: dict | None = None, *, raw_dir: Path | None = None): ...
       def available(self, sandbox) -> bool: ...  # sandbox.run(["mytool", "--version"]).ok
       def version(self, sandbox) -> ScannerVersion: ...  # tool + vulnerability DB version/date
       def scan(self, sandbox, workspace, targets=None) -> ScanReport: ...
       def parse(self, raw: str) -> ScanReport: ...  # PURE: no I/O, no subprocess
   ```

   - `available()` must return `False` (never raise) when the binary is missing; the sandbox
     reports a missing executable as exit code 127.
   - `scan()` runs the tool with `sandbox.run(argv, cwd=workspace)`, saves the raw output under
     `raw_dir` (**never inside the workspace**: it would show up in the diff), and returns
     `parse(raw)` with `scanner_version`, `db_version`, `targets` and `raw_path` filled in.
     Decide which exit codes mean success (many tools exit 1 when they find something) and
     raise `ananke.scanners.ScannerError` for anything else.
   - `parse()` must not raise on an empty report (`""`, `[]`, `{"results": []}`, ...).
2. **One fixture** of the tool's real JSON output under
   `tests/fixtures/scanner_output/<name>/` (ideally a before/after pair against
   `tests/fixtures/repos/`), plus a parse test in `tests/unit/test_scanner_<name>.py` that
   asserts specific advisory ids, packages, versions and locations, and a `delta()` test.
3. **One registry line.** Either add the class to `_builtin_classes()` in
   `src/ananke/scanners/__init__.py` (and its name to `BUILTIN`), or ship it as a separate
   package exposing an entry point:

   ```toml
   [project.entry-points."ananke.scanners"]
   mytool = "my_pkg.scanner:MyScanner"   # a class, a factory, or an instance
   ```

   `build_scanners()` calls `registry.load_entry_points()`, so an installed plugin is picked
   up without touching Ananke. (Entry-point scanners are constructed with no arguments.)
4. **One install line** in `docker/worker.Dockerfile` so the binary exists in the worker image
   (pin the version; pre-bake any vulnerability DB the tool needs, as Trivy does).
5. **Options** under `scanners.<name>` in `ananke.yaml`; the scanner receives them as a dict
   from `ScannersConfig.options_for(name)`. Enable it by adding the name to
   `scanners.enabled` (the order there is the row order of the PR's proof-of-work table).

`tests/unit/test_scanner_plugin_checklist.py` follows this checklist with a toy scanner.

## ScanFinding conventions

| Field | Convention |
|---|---|
| `id` | The CVE when the tool knows one; else the advisory id (GHSA-..., PYSEC-...); for misconfig/secret findings the tool's rule id (`AVD-DS-0002`, `aws-access-token`). |
| `aliases` | Every other identifier of the same advisory (GHSA, PYSEC, vendor ids). gitleaks stores its `Fingerprint` (`file:rule:line`). |
| `kind` | `dependency` for package advisories (Trivy `lang-pkgs`/`os-pkgs`, OSV), `iac` for misconfigurations, `secret` for leaked credentials, `container` / `sast` reserved. |
| `severity` | `critical/high/medium/low/unknown` via `ananke.model.normalize_severity`. OSV uses the group's CVSS `max_severity` (>=9 critical, >=7 high, >=4 medium, >0 low), falling back to `database_specific.severity`. gitleaks findings are always `high`. |
| `package`, `installed_version` | As reported; `None` for non-dependency findings. |
| `fixed_version` | Trivy's string kept verbatim (it may list several: `"2.0.6, 1.26.17"`); OSV: the smallest `fixed` event above the installed version for that package/ecosystem (GIT ranges ignored). |
| `location` | Workspace-relative path: the manifest/lockfile for dependencies (`uv.lock`), `file:line` for secrets and misconfigurations. Absolute paths under the workspace are made relative so before/after (and Trivy/OSV) agree. |
| `title` | One-line summary from the tool. |

OSV lists one advisory several times (one record per database, e.g. GHSA and PYSEC for the same
CVE). The OSV plugin merges records whose ids/aliases overlap into a single finding.

## Secrets: the redaction rule

A secret-kind finding **never** carries the secret. gitleaks `Secret`/`Match` and Trivy secret
`Match`/`Code` fields are not copied into any `ScanFinding` field, log line, PR body or issue.
Only the rule id, description, `file:line` and (gitleaks) fingerprint are kept. The raw report on
disk does contain the secret; that is why `raw_dir` lives outside the workspace and outside
anything that is pushed. Tests assert the secret string appears nowhere in a dumped `ScanReport`.

## Delta identity

`delta(before, after)` compares two reports **from the same scanner**. Two findings are the same
when they share **any** id or alias (case-insensitive) **and** have the same `package` **and**
the same `location`. So a Trivy finding with id `CVE-2023-32681` and an OSV-style finding with
id `GHSA-j8r2-6x86-q33q` + alias `CVE-2023-32681` match. Results:

- `resolved` — before-findings with no match after (the fix worked);
- `remaining` — after-findings that match a before-finding;
- `introduced` — after-findings with no match before (regressions; `no_regressions` and
  `no_secrets` in verify read these).

Keep `location` stable between runs (relative paths, no temp-dir prefixes), or every finding
looks resolved-and-introduced. Line-based locations (secrets, misconfig) move when lines move;
that is accepted as conservative.

## Availability: `ananke scanners`

`ananke scanners` lists every registered scanner (built-ins plus entry points) with its kinds,
ecosystems, whether it is enabled in `ananke.yaml`, and whether its binary is present —
`scanner.available(sandbox)`, i.e. `<binary> --version` exits 0 in the sandbox — plus the tool
and DB versions from `scanner.version(sandbox)` when available. On a dev host without the
binaries every scanner shows as unavailable; parse tests still run from fixtures.

## Built-in commands

```text
trivy fs --scanners vuln,misconfig,secret --format json [--ignore-unfixed] --skip-db-update \
    [--cache-dir <scanners.trivy.cache_dir>] <workspace>                 # success: exit 0
osv-scanner scan --format json [--offline] -r <workspace>                 # success: exit 0 or 1
osv-scanner scan --format json [--offline] --lockfile <t1> --lockfile <t2>   # with targets
gitleaks dir <path> --report-format json --report-path <raw_dir>/<file>.json \
    --no-banner --exit-code 1 [--config <scanners.gitleaks.config>]       # success: exit 0 or 1
```

## Worker image and database

M1 builds the pinned scanner tools from their official releases in
[`docker/worker.Dockerfile`](../docker/worker.Dockerfile). The pinned versions match the schemas the
parse fixtures follow (Trivy 0.76.2, OSV-Scanner 2.7.1, gitleaks 8.30.1). Vulnerability databases
are baked into the image so runs are reproducible and need no database egress:

- Trivy's database lives under `/opt/ananke/cache/trivy`, and runs use `--skip-db-update`.
- OSV-Scanner's offline databases for PyPI, npm and Go live under `/opt/ananke/cache/osv-scanner`
  (`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`). Runs use `--offline`.

A configured, non-empty `sandbox.scanner_db_volume` holding Trivy's `trivy.db` and
`metadata.json` replaces the baked Trivy database read-only. Keep that directory populated from a
trusted refresh process (PLAN.md M4). Ananke does not update scanner databases during a work item.

Raw reports are stored outside the checkout. Trivy and OSV return JSON on stdout. For gitleaks,
the host copies a transient report from the container to the host raw directory and removes the
container copy before agent tools run. Raw reports may contain secret material and are never
mounted into the agent container.

For outbound package access, `sandbox.network` must name a Docker network protected by a host
firewall or egress proxy that applies `sandbox.network_allowlist`. Standard Docker bridge
networking is unrestricted and does not satisfy this requirement. See [`TRUST.md`](TRUST.md).

## How the verify gate uses scanners

`targets_resolved` asks every enabled scanner whose `kinds` include `dependency` and whose
`ecosystems` include the finding's ecosystem (or `*`) whether the finding is still present after
the change. A covering scanner that reports nothing counts as clean. A finding that no enabled
scanner covers fails the check, so enable at least one dependency scanner for each ecosystem you
patch. `no_secrets` reads `introduced` findings of kind `secret` from every scanner.
