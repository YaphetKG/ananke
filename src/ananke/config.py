"""Configuration models for `ananke.yaml` (PLAN.md §7.1) and `ANANKE.md` front matter (§7.2).

Loading rules:
- `$VAR` / `${VAR}` in any string value are replaced from the environment. A value that is
  exactly one unset variable becomes null (so optional secrets simply stay unset); an unset
  variable embedded in a longer string becomes "".
- A leading `~` in any string value is expanded to the home directory.
- Path-typed fields that are still relative resolve against the config file's directory.
- Unknown keys are ignored with a logged warning (`config_unknown_key key=<dotted.path>`).
- Validation failures raise `ConfigError`, whose message names each offending dotted key.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal, get_args, get_origin

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
    ValidationError,
    ValidationInfo,
)

from ananke.logging import get_logger
from ananke.model import Severity

log = get_logger(__name__)

# ---------------------------------------------------------------------------------------------
# Expansion helpers


_VAR_RE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))"
)


def expand_string(value: str, env: dict[str, str] | None = None) -> str | None:
    """Expand `$VAR`, `${VAR}` and a leading `~`. Returns None if the whole value is one unset
    variable."""
    env = os.environ if env is None else env  # type: ignore[assignment]
    whole = _VAR_RE.fullmatch(value)
    if whole:
        name = whole.group("braced") or whole.group("bare")
        if name not in env or env[name] == "":
            return None
    out = _VAR_RE.sub(lambda m: env.get(m.group("braced") or m.group("bare"), ""), value)
    if out.startswith("~"):
        out = os.path.expanduser(out)
    return out


def expand_tree(data: Any, env: dict[str, str] | None = None) -> Any:
    """Recursively apply `expand_string` to every string value (keys are left alone)."""
    if isinstance(data, str):
        return expand_string(data, env)
    if isinstance(data, dict):
        return {k: expand_tree(v, env) for k, v in data.items()}
    if isinstance(data, list):
        return [expand_tree(v, env) for v in data]
    return data


def _resolve_path(value: Path | None, info: ValidationInfo) -> Path | None:
    if value is None:
        return None
    value = Path(os.path.expanduser(str(value)))
    base = (info.context or {}).get("base_dir") if info.context else None
    if not value.is_absolute() and base is not None:
        value = Path(base) / value
    return value


ConfigPath = Annotated[Path, AfterValidator(_resolve_path)]


class _Section(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_default=True)


# ---------------------------------------------------------------------------------------------
# ananke.yaml


class TrivyConfig(_Section):
    scanners: list[str] = Field(default_factory=lambda: ["vuln", "misconfig", "secret"])
    ignore_unfixed: bool = True
    image_mode: bool = False
    cache_dir: ConfigPath | None = None  # --cache-dir (vulnerability DB location)
    timeout_s: int | None = Field(None, gt=0)  # None = the scanner's built-in default


class OsvConfig(_Section):
    offline: bool = True
    timeout_s: int | None = Field(None, gt=0)


class GitleaksConfig(_Section):
    config: ConfigPath | None = None  # custom gitleaks.toml rules (--config)
    timeout_s: int | None = Field(None, gt=0)


class ScannersConfig(_Section):
    # Extra keys are allowed here: `scanners.<name>` holds options for third-party scanners.
    model_config = ConfigDict(extra="allow", validate_default=True)

    enabled: list[str] = Field(default_factory=lambda: ["trivy", "osv", "gitleaks"])
    sweep_interval_s: int = Field(86400, ge=0)
    max_db_age_days: int = Field(7, ge=0)
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    osv: OsvConfig = Field(default_factory=OsvConfig)
    gitleaks: GitleaksConfig = Field(default_factory=GitleaksConfig)

    def options_for(self, name: str) -> dict[str, Any]:
        """Options dict for scanner `name` (`scanners.<name>`), {} if none configured.

        Unset optional fields (None) are omitted so scanners fall back to their defaults."""
        if name in type(self).model_fields and isinstance(getattr(self, name), BaseModel):
            return getattr(self, name).model_dump(exclude_none=True)
        extra = (self.model_extra or {}).get(name)
        return dict(extra) if isinstance(extra, dict) else {}


class PollingConfig(_Section):
    interval_s: int = Field(600, gt=0)


class WorkspaceConfig(_Section):
    root: ConfigPath = Path("~/ananke-workspaces")


class AgentConfig(_Section):
    model: str = "claude-opus-5-5"
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    max_concurrent: int = Field(3, ge=1)
    max_concurrent_per_repo: int = Field(1, ge=1)
    max_turns: int = Field(40, ge=1)
    max_attempts: int = Field(3, ge=1)
    max_retry_backoff_s: int = Field(300, ge=0)
    stall_timeout_s: int = Field(600, gt=0)
    run_timeout_s: int = Field(3600, gt=0)
    token_budget_per_run: int = Field(2_000_000, ge=0)
    daily_token_budget: int = Field(20_000_000, ge=0)
    summarization: bool = False


class AutoMergeConfig(_Section):
    enabled: bool = False
    max_bump: Literal["patch", "minor"] = "patch"
    min_severity: Severity = "high"


class PolicyConfig(_Section):
    min_severity: Severity = "medium"
    require_fixed_version: bool = True
    regression_severity: Severity = "high"
    grouping: Literal["per_manifest", "per_package", "per_repo"] = "per_manifest"
    ignore_paths: list[str] = Field(default_factory=lambda: ["docs/**", "examples/**"])
    dependabot_prs: Literal["adopt", "ignore", "supersede"] = "supersede"
    auto_merge: AutoMergeConfig = Field(default_factory=AutoMergeConfig)
    failure_issue: bool = True
    declined_cooldown_days: int = Field(7, ge=0)
    # Referenced elsewhere in the plan (§13, §5); not shown in the §7.1 example.
    bump_strategy: Literal["minimal", "latest"] = "minimal"
    allow_dockerfile: bool = False


class GitHubConfig(_Section):
    app_id: str | None = None
    installation_id: str | None = None
    private_key_path: ConfigPath | None = None
    token: SecretStr | None = None  # PAT fallback (PLAN.md §12.2), e.g. `$GITHUB_TOKEN`
    api_url: str = "https://api.github.com"

    @property
    def auth_mode(self) -> Literal["app", "token", "none"]:
        if self.app_id and self.installation_id and self.private_key_path:
            return "app"
        if self.token is not None and self.token.get_secret_value():
            return "token"
        return "none"


DEFAULT_NETWORK_ALLOWLIST = [
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "proxy.golang.org",
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
]


class SandboxConfig(_Section):
    image: str = "ghcr.io/renci/ananke-worker:latest"
    network_allowlist: list[str] = Field(default_factory=lambda: list(DEFAULT_NETWORK_ALLOWLIST))
    cpu: float = Field(2, gt=0)
    memory: str = "4g"
    scanner_db_volume: ConfigPath = Path("~/ananke-scanner-db")
    allow_local: bool = False  # permit the non-isolated LocalSandbox (dev/test only, §15)


class NotifyConfig(_Section):
    slack_webhook: SecretStr | None = None


class ServerConfig(_Section):
    port: int = Field(0, ge=0, le=65535)  # 0 = disabled
    host: str = "127.0.0.1"


SourceName = Literal["github_dependabot", "local_sweep", "github_code_scanning"]


class AnankeConfig(_Section):
    repos: list[str] = Field(default_factory=list)
    sources: list[SourceName] = Field(
        default_factory=lambda: ["github_dependabot", "local_sweep"]  # type: ignore[arg-type]
    )
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    polling: PollingConfig = Field(default_factory=PollingConfig)
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    live_model: bool = False

    _path: Path | None = PrivateAttr(default=None)
    _unknown_keys: list[str] = PrivateAttr(default_factory=list)

    @property
    def path(self) -> Path | None:
        """The file this config was loaded from (None if built in code)."""
        return self._path

    @property
    def base_dir(self) -> Path:
        return self._path.parent if self._path else Path.cwd()

    @property
    def unknown_keys(self) -> list[str]:
        """Dotted paths of keys that were ignored during load."""
        return list(self._unknown_keys)


# ---------------------------------------------------------------------------------------------
# ANANKE.md front matter


class HooksConfig(_Section):
    after_create: str = ""
    before_run: str = ""
    after_run: str = ""
    before_remove: str = ""
    timeout_s: int = Field(60, gt=0)


DEFAULT_ALLOWED_PATHS = [
    "src/**",
    "lib/**",
    "app/**",
    "pyproject.toml",
    "uv.lock",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "**/requirements*.txt",
    "requirements*.txt",
    "**/package.json",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/go.mod",
    "**/go.sum",
]
DEFAULT_PROTECTED_PATHS = [".github/workflows/**", "**/*.pem", "**/*secret*"]


class RepoWorkflowConfig(_Section):
    """YAML front matter of a target repo's `ANANKE.md`."""

    setup_command: str | None = None
    test_command: str | None = None
    tests: Literal["required", "advisory"] = "required"
    allowed_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_PATHS))
    protected_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_PROTECTED_PATHS))
    max_diff_lines: int = Field(800, gt=0)
    reviewers: list[str] = Field(default_factory=list)
    hooks: HooksConfig = Field(default_factory=HooksConfig)


# ---------------------------------------------------------------------------------------------
# Errors, unknown-key detection, loaders


class ConfigError(ValueError):
    """Invalid configuration. `.problems` is a list of (dotted_key, message)."""

    def __init__(self, source: str, problems: list[tuple[str, str]]):
        self.source = source
        self.problems = problems
        lines = [f"{key}: {msg}" for key, msg in problems]
        super().__init__(f"invalid config {source}:\n  " + "\n  ".join(lines))


def _model_of(annotation: Any) -> type[BaseModel] | None:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    if get_origin(annotation) is not None:
        for arg in get_args(annotation):
            m = _model_of(arg)
            if m is not None:
                return m
    return None


def find_unknown_keys(model: type[BaseModel], data: Any, prefix: str = "") -> list[str]:
    """Dotted paths of keys in `data` that `model` does not declare (recursing into sections).
    Sections that allow extra keys (e.g. `scanners`) don't report their extras."""
    if not isinstance(data, dict):
        return []
    unknown: list[str] = []
    allows_extra = model.model_config.get("extra") == "allow"
    for key, value in data.items():
        dotted = f"{prefix}{key}"
        field = model.model_fields.get(str(key))
        if field is None:
            if not allows_extra:
                unknown.append(dotted)
            continue
        sub = _model_of(field.annotation)
        if sub is not None:
            unknown += find_unknown_keys(sub, value, dotted + ".")
    return unknown


def _problems(exc: ValidationError) -> list[tuple[str, str]]:
    out = []
    for err in exc.errors():
        key = ".".join(str(p) for p in err["loc"]) or "<root>"
        out.append((key, err["msg"]))
    return out


def _validate(model: type[BaseModel], data: dict[str, Any], source: str, base_dir: Path | None):
    unknown = find_unknown_keys(model, data)
    for key in unknown:
        log.warning("config_unknown_key", key=key, source=source)
    try:
        obj = model.model_validate(data, context={"base_dir": base_dir})
    except ValidationError as exc:
        raise ConfigError(source, _problems(exc)) from None
    return obj, unknown


def config_from_dict(
    data: dict[str, Any] | None,
    *,
    base_dir: Path | None = None,
    source: str = "<dict>",
    env: dict[str, str] | None = None,
) -> AnankeConfig:
    """Build an AnankeConfig from already-parsed YAML data (expansion is applied here)."""
    data = expand_tree(data or {}, env)
    if not isinstance(data, dict):
        raise ConfigError(source, [("<root>", "top level must be a mapping")])
    cfg, unknown = _validate(AnankeConfig, data, source, base_dir)
    cfg._unknown_keys = unknown
    return cfg


def load_config(path: Path | str, *, env: dict[str, str] | None = None) -> AnankeConfig:
    """Load and validate `ananke.yaml`. Raises ConfigError (naming keys) or FileNotFoundError."""
    path = Path(path).expanduser().resolve()
    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(str(path), [("<yaml>", str(exc))]) from None
    cfg = config_from_dict(data, base_dir=path.parent, source=str(path), env=env)
    cfg._path = path
    return cfg


_FRONT_MATTER_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)


def split_front_matter(text: str) -> tuple[dict[str, Any], str]:
    """Split a markdown document into (front-matter mapping, body).

    No front matter -> ({}, text).
    """
    m = _FRONT_MATTER_RE.match(text)
    if not m:
        return {}, text
    data = yaml.safe_load(m.group(1)) or {}
    if not isinstance(data, dict):
        raise ConfigError("<front matter>", [("<root>", "front matter must be a mapping")])
    return data, text[m.end() :]


def parse_repo_workflow(
    text: str, *, source: str = "ANANKE.md", env: dict[str, str] | None = None
) -> tuple[RepoWorkflowConfig, str]:
    """Parse an ANANKE.md document into (RepoWorkflowConfig, prompt body)."""
    try:
        data, body = split_front_matter(text)
    except yaml.YAMLError as exc:
        raise ConfigError(source, [("<yaml>", str(exc))]) from None
    cfg, _ = _validate(RepoWorkflowConfig, expand_tree(data, env), source, None)
    return cfg, body
