# Scanner output fixtures

**Every JSON file in this directory is HAND-WRITTEN from the documented output schema. None of
it is real tool output.** The host these were written on has no trivy, osv-scanner or gitleaks
binaries and no Docker. Replace them with real output by running
`scripts/regen_scanner_fixtures.sh` on a machine that has the tools (see below).

## How they were written

The advisory content is real; only the scanner wrapping is hand-assembled.

- Advisory data (ids, aliases, summaries, descriptions, CVSS vectors, CWEs, affected ranges,
  fixed versions) comes from the public GitHub advisory API (`api.github.com/advisories/<GHSA>`)
  and the OSV API (`api.osv.dev/v1/vulns/<id>`), fetched 2026-11-12. The OSV `vulnerabilities[]`
  entries are the unmodified OSV records.
- The surrounding structure follows the schema of each tool's latest release on 2026-11-12:

| Tool | Schema followed | Source used |
|---|---|---|
| Trivy | v0.76.2, JSON report `SchemaVersion: 2` | `pkg/types/report.go` and `pkg/types/vulnerability.go` on `main`; trivy-db `pkg/vulnsrc/osv/osv.go` (CVE as `VulnerabilityID`, GHSA in `VendorIDs`) |
| OSV-Scanner | v2.7.1 | `pkg/models/results.go` on `main` and https://google.github.io/osv-scanner/output/ |
| gitleaks | v8.30.1 | `report/finding.go` on `master` |

- Synthetic values that a real run would produce differently: Trivy `ReportID`, `CreatedAt`,
  `Fingerprint` and `PkgIdentifier.UID` (deterministic hashes); Trivy `PublishedDate` /
  `LastModifiedDate` (taken from GitHub, not NVD); the `/scan/...` paths in OSV output; the
  gitleaks `Entropy` (computed with the same Shannon formula gitleaks uses).

## What the files contain

Before/after for the fixture repos in `tests/fixtures/repos/`:

| File | Advisories (CVE / GHSA) |
|---|---|
| `trivy/before_py.json`, `osv/before_py.json` | requests 2.25.1: CVE-2023-32681 / GHSA-j8r2-6x86-q33q, CVE-2024-35195 / GHSA-9wx4-h78v-vm56; urllib3 1.26.5: CVE-2023-43804 / GHSA-v845-jxx5-vc9f, CVE-2023-45803 / GHSA-g4mx-q9vg-27p4, CVE-2024-37891 / GHSA-34jh-p97f-mpxf (OSV also lists the PYSEC ids) |
| `trivy/after_py.json`, `osv/after_py.json` | none |
| `trivy/before_js.json`, `osv/before_js.json` | lodash 4.17.15: CVE-2020-8203 / GHSA-p6mc-m468-83gw, CVE-2021-23337 / GHSA-35jh-r3h4-6jhm, CVE-2020-28500 / GHSA-29mw-wpgm-hmr9 |
| `trivy/after_js.json`, `osv/after_js.json` | none |
| `gitleaks/one_secret.json` | one `aws-access-token` finding for `AKIAIOSFODNN7EXAMPLE`, the AWS documentation example key (not a credential) |
| `gitleaks/clean.json` | `[]` |

**These are a curated subset of what real scanners report today.** The `before_*` files list
only the advisories that the fix versions used by the tests (requests 2.32.3, urllib3 2.2.3,
lodash 4.17.21) resolve, and the `after_*` files are empty. Real output on 2026-11-12 also
includes advisories that those versions do **not** fix, in both `before` and `after`. Examples:
requests CVE-2024-47081 (fixed 2.32.4) and CVE-2026-25645 (2.33.0); urllib3 CVE-2025-50181 /
CVE-2025-50182 (2.5.0), CVE-2025-66418 / CVE-2025-66471 (2.6.0) and later; lodash CVE-2025-13465
(4.17.23) and CVE-2026-4800 (4.18.0); transitive idna 2.10 CVE-2024-3651. So once real output
replaces these files, tests should assert on specific ids rather than on "after is empty".

The gitleaks default config allowlists AWS keys ending in `EXAMPLE`, so a stock gitleaks run
would *not* report the example key. The regen script uses a minimal config that keeps the
upstream `aws-access-token` rule but drops that allowlist.

## Regenerating real output

```bash
# needs trivy, osv-scanner, gitleaks, uv and npm on PATH
scripts/regen_scanner_fixtures.sh
# optional: different fix targets
PY_REQUESTS_FIX=2.33.0 PY_URLLIB3_FIX=2.8.0 JS_LODASH_FIX=4.18.0 scripts/regen_scanner_fixtures.sh
```

The script copies each fixture repo to a temp dir, scans it, applies the fix there, and scans
again. It writes all files here plus `VERSIONS.md` with the exact tool versions, and rewrites
this README to say the files are real output. It never modifies the committed fixture repos.
