"""Configuration loading: YAML file + Pydantic v2 validation."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class AuthCredential(BaseModel):
    """A single named credential for auth testing."""

    name: str = "default"
    method: Literal["cookie", "bearer", "header"] = "cookie"
    cookie_name: str = ""
    cookie_value: str = ""
    bearer_token: str = ""
    header_name: str = ""
    header_value: str = ""


class AuthConfig(BaseModel):
    """Authentication injection settings."""

    method: Literal["cookie", "bearer", "header", "localStorage", "none"] = "none"
    cookie_name: str = ""
    cookie_value: str = ""
    bearer_token: str = ""
    header_name: str = ""
    header_value: str = ""
    local_storage: dict[str, str] = Field(default_factory=dict)
    login_url: str = "/login"
    auth_indicator: str = ""
    credentials: list[AuthCredential] = Field(default_factory=list)


class CrawlConfig(BaseModel):
    """Crawl behavior settings."""

    max_depth: int = 10
    max_nodes: int = 500
    respect_robots: bool = True
    follow_external: bool = False
    url_exclude_patterns: list[str] = Field(default_factory=list)
    request_delay_ms: int = 100
    render_js: bool = False


class CaptureConfig(BaseModel):
    """Capture behavior settings."""

    concurrency: int = 10
    timeout_ms: int = 30000
    screenshot: bool = True
    viewport_width: int = 1280
    viewport_height: int = 720


_ALL_STANDARDS = [
    "owasp_top10_2021", "iso_27001_2022", "soc2", "fedramp_rev5", "hipaa",
    "pci_dss_v4", "nist_csf_2", "gdpr_ccpa", "ofac", "cia_triad",
    "privacy_by_design", "access_control", "data_breach_notification", "cjis",
]

_STANDARD_ALIASES = {
    "all": "all",
    "owasp": "owasp_top10_2021",
    "owasp_top10": "owasp_top10_2021",
    "owasp_top10_2021": "owasp_top10_2021",
    "iso": "iso_27001_2022",
    "iso27001": "iso_27001_2022",
    "iso_27001": "iso_27001_2022",
    "iso_27001_2022": "iso_27001_2022",
    "soc": "soc2",
    "soc2": "soc2",
    "soc_2": "soc2",
    "fedramp": "fedramp_rev5",
    "fedramp_rev5": "fedramp_rev5",
    "hipaa": "hipaa",
    "hippa": "hipaa",
    "pci": "pci_dss_v4",
    "pci_dss": "pci_dss_v4",
    "pci_dss_v4": "pci_dss_v4",
    "nist": "nist_csf_2",
    "nist_csf": "nist_csf_2",
    "nist_csf_2": "nist_csf_2",
    "gdpr": "gdpr_ccpa",
    "ccpa": "gdpr_ccpa",
    "gdpr_ccpa": "gdpr_ccpa",
    "ofac": "ofac",
    "cia": "cia_triad",
    "cia_triad": "cia_triad",
    "privacy": "privacy_by_design",
    "privacy_by_design": "privacy_by_design",
    "access_control": "access_control",
    "data_breach": "data_breach_notification",
    "data_breach_notification": "data_breach_notification",
    "cjis": "cjis",
}


def normalize_compliance_standards(value: str | list[str] | None) -> list[str]:
    """Normalize user-facing compliance names to bundled mapping keys."""
    if value is None:
        return list(_ALL_STANDARDS)
    if isinstance(value, str):
        raw_items = [item.strip() for item in value.replace(";", ",").split(",")]
    else:
        raw_items = [str(item).strip() for item in value]

    normalized: list[str] = []
    for item in raw_items:
        if not item:
            continue
        key = item.lower().replace("-", "_").replace(" ", "_").replace(".", "_")
        mapped = _STANDARD_ALIASES.get(key)
        if mapped is None:
            raise ValueError(f"Unknown compliance standard: {item}")
        if mapped == "all":
            return list(_ALL_STANDARDS)
        if mapped not in normalized:
            normalized.append(mapped)
    return normalized or list(_ALL_STANDARDS)

_DEFAULT_SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD",
    "/.svn/entries",
    "/wp-admin/", "/wp-login.php",
    "/phpinfo.php",
    "/server-status", "/server-info",
    "/.well-known/security.txt",
    "/.htaccess", "/.htpasswd",
    "/backup.sql", "/dump.sql",
    "/web.config",
    "/admin", "/console",
    "/api/docs", "/swagger.json", "/openapi.json",
]


class ComplianceConfig(BaseModel):
    """Compliance standards configuration."""

    enabled: bool = True
    standards: list[str] = Field(default_factory=lambda: list(_ALL_STANDARDS))
    skip_standards: list[str] = Field(default_factory=list)
    include_untestable: bool = True
    custom_mappings_path: str = ""

    @field_validator("standards")
    @classmethod
    def _normalize_standards(cls, v: list[str]) -> list[str]:
        return normalize_compliance_standards(v)

    @field_validator("skip_standards")
    @classmethod
    def _normalize_skip_standards(cls, v: list[str]) -> list[str]:
        if not v:
            return []
        return normalize_compliance_standards(v)


class SecurityConfig(BaseModel):
    """Extended security check configuration."""

    active_probing: bool = False
    tls_check: bool = True
    sensitive_file_detection: bool = True
    sensitive_file_paths: list[str] = Field(default_factory=lambda: list(_DEFAULT_SENSITIVE_PATHS))


class SourceAnalysisConfig(BaseModel):
    """Repository/source analysis configuration."""

    enabled: bool = False
    max_file_bytes: int = 1_000_000
    include_patterns: list[str] = Field(default_factory=list)
    exclude_dirs: list[str] = Field(default_factory=lambda: [
        ".git", ".hg", ".svn", ".kin",
        "node_modules", ".venv", "venv", "__pycache__",
        "dist", "build", "coverage", ".next",
        "webprobe-runs", "runs",
    ])
    exclude_patterns: list[str] = Field(default_factory=list)


class RuntimeCanaryConfig(BaseModel):
    """Safe runtime input canary probing configuration."""

    enabled: bool = False
    max_inputs: int = 50
    concurrency: int = 4
    timeout_ms: int = 10000
    include_links: bool = True
    include_get_forms: bool = True
    methods: list[str] = Field(default_factory=lambda: ["GET"])
    user_agent: str = "webprobe-canary/0.6"
    canary_prefix: str = "wp_canary"


class WebprobeConfig(BaseModel):
    """Top-level configuration."""

    auth: AuthConfig = Field(default_factory=AuthConfig)
    crawl: CrawlConfig = Field(default_factory=CrawlConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    output_dir: str = "./webprobe-runs"
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    source_analysis: SourceAnalysisConfig = Field(default_factory=SourceAnalysisConfig)
    runtime_canary: RuntimeCanaryConfig = Field(default_factory=RuntimeCanaryConfig)

    @model_validator(mode="after")
    def _force_js_for_localstorage_auth(self) -> WebprobeConfig:
        # localStorage injection only works through a real browser; the aiohttp
        # crawl path can't populate it. Force JS rendering so Phase 1 authenticates.
        if self.auth.method == "localStorage" and not self.crawl.render_js:
            self.crawl.render_js = True
        return self


_SEARCH_PATHS = [
    Path("webprobe.yaml"),
    Path.home() / ".webprobe" / "webprobe.yaml",
]


def load_config(path: str | Path | None = None) -> WebprobeConfig:
    """Load config from explicit path, ./webprobe.yaml, ~/.webprobe/webprobe.yaml, or defaults."""
    if path is not None:
        p = Path(path)
        if p.exists():
            return WebprobeConfig.model_validate(yaml.safe_load(p.read_text()) or {})
        raise FileNotFoundError(f"Config not found: {p}")

    for p in _SEARCH_PATHS:
        if p.exists():
            return WebprobeConfig.model_validate(yaml.safe_load(p.read_text()) or {})

    return WebprobeConfig()
