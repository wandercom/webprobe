"""Stable data models for webprobe. Schema version is pinned for cross-run aggregation."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Literal, Union
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


SCHEMA_VERSION = "1.3"


# ---- Enums ----


class AuthContext(str, Enum):
    anonymous = "anonymous"
    authenticated = "authenticated"


class DiscoveryMethod(str, Enum):
    sitemap = "sitemap"
    robots = "robots"
    crawl = "crawl"
    framework = "framework"
    manual = "manual"


class ResourceType(str, Enum):
    document = "document"
    script = "script"
    stylesheet = "stylesheet"
    image = "image"
    font = "font"
    media = "media"
    xhr = "xhr"
    fetch = "fetch"
    websocket = "websocket"
    other = "other"


class ConsoleMessageLevel(str, Enum):
    log = "log"
    warning = "warning"
    error = "error"
    info = "info"
    debug = "debug"


# ---- Timing ----


class TimingData(BaseModel):
    """Timing for a single operation. All values in milliseconds."""

    started_at: str  # ISO 8601
    duration_ms: float
    ttfb_ms: float | None = None


# ---- Resources ----


class Resource(BaseModel):
    """A single subresource loaded during a page visit."""

    url: str
    resource_type: ResourceType
    status_code: int | None = None
    size_bytes: int | None = None
    timing: TimingData | None = None
    mime_type: str = ""
    has_integrity: bool = False


class ConsoleMessage(BaseModel):
    """A browser console message captured during page visit."""

    level: ConsoleMessageLevel
    text: str
    url: str = ""
    line: int | None = None


# ---- Node ----


class NodeState(BaseModel):
    """State identity for a node. URL-based, extensible for DOM fingerprinting."""

    url: str

    def identity_key(self) -> str:
        return self.url


class CookieInfo(BaseModel):
    """Security-relevant cookie attributes captured during visit."""

    name: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str = ""  # "Strict", "Lax", "None", or ""
    expires: float = -1  # Unix timestamp, -1 = session cookie


class ResponseHeaders(BaseModel):
    """Security-relevant response headers from the document response."""

    raw: dict[str, str] = Field(default_factory=dict)


class FormInfo(BaseModel):
    """A form discovered on the page."""

    action: str = ""
    method: str = "GET"
    has_csrf_token: bool = False
    has_password_field: bool = False
    autocomplete_off: bool = False
    input_names: list[str] = Field(default_factory=list)
    input_types: list[str] = Field(default_factory=list)


class SecuritySeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class SecurityCategory(str, Enum):
    headers = "headers"
    cookies = "cookies"
    xss = "xss"
    mixed_content = "mixed_content"
    cors = "cors"
    information_disclosure = "information_disclosure"
    forms = "forms"
    tls = "tls"
    accessibility = "accessibility"
    visual = "visual"
    exploration = "exploration"
    injection = "injection"
    auth_session = "auth_session"
    privacy = "privacy"
    supply_chain = "supply_chain"
    sensitive_files = "sensitive_files"
    advocate = "advocate"
    secrets = "secrets"
    cryptography = "cryptography"
    authorization = "authorization"
    ai_injection = "ai_injection"
    source_analysis = "source_analysis"


class ComplianceViolation(BaseModel):
    """A single compliance standard control violated by a finding."""

    standard: str
    standard_name: str
    control_id: str
    control_name: str
    testable: str = "yes"


class SecurityFinding(BaseModel):
    """A single security finding, optionally consolidated across multiple URLs."""

    category: SecurityCategory
    severity: SecuritySeverity
    title: str
    detail: str = ""
    evidence: str = ""
    url: str = ""
    auth_context: AuthContext = AuthContext.anonymous
    affected_urls: list[str] = Field(default_factory=list)
    affected_count: int = 0
    compliance_violations: list[ComplianceViolation] = Field(default_factory=list)
    source_path: str = ""
    source_line: int | None = None
    source_column: int | None = None
    source_excerpt: str = ""
    rule_id: str = ""
    confidence: str = ""
    source_context: dict[str, str] = Field(default_factory=dict)


class NodeCapture(BaseModel):
    """Capture data for a single node visit in a single auth context."""

    auth_context: AuthContext
    http_status: int | None = None
    timing: TimingData | None = None
    dom_content_loaded_ms: float | None = None
    load_event_ms: float | None = None
    page_title: str = ""
    page_text: str = ""
    resources: list[Resource] = Field(default_factory=list)
    console_messages: list[ConsoleMessage] = Field(default_factory=list)
    outgoing_links: list[str] = Field(default_factory=list)
    screenshot_path: str = ""
    response_headers: ResponseHeaders = Field(default_factory=ResponseHeaders)
    cookies: list[CookieInfo] = Field(default_factory=list)
    forms: list[FormInfo] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)


class Node(BaseModel):
    """A node in the site state graph."""

    id: str
    state: NodeState
    discovered_via: DiscoveryMethod
    requires_auth: bool | None = None
    auth_contexts_available: list[AuthContext] = Field(default_factory=list)
    captures: list[NodeCapture] = Field(default_factory=list)
    depth: int = 0


# ---- Edge ----


class Edge(BaseModel):
    """A directed edge (link/action) between two nodes."""

    source: str
    target: str
    link_text: str = ""
    discovered_via: DiscoveryMethod = DiscoveryMethod.crawl
    auth_context: AuthContext = AuthContext.anonymous
    verified: bool = False


# ---- TLS ----


class TlsInfo(BaseModel):
    """TLS connection details for the target host."""

    protocol_version: str = ""
    cipher_suite: str = ""
    forward_secrecy: bool = False
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_not_after: str = ""
    cert_days_remaining: int = 0
    cert_self_signed: bool = False
    cert_key_type: str = ""
    cert_key_size: int = 0
    san_names: list[str] = Field(default_factory=list)


# ---- Graph ----


class SiteGraph(BaseModel):
    """The complete site graph discovered during mapping."""

    nodes: dict[str, Node] = Field(default_factory=dict)
    edges: list[Edge] = Field(default_factory=list)
    root_url: str = ""
    seed_urls: list[str] = Field(default_factory=list)
    tls_info: TlsInfo | None = None


# ---- Analysis Results ----


class BrokenLink(BaseModel):
    source: str
    target: str
    status_code: int | None = None
    error: str = ""


class AuthBoundaryViolation(BaseModel):
    """A page that should require auth but is accessible without it."""

    url: str
    expected_auth: bool
    actual_accessible_anonymous: bool
    evidence: str = ""


class TimingOutlier(BaseModel):
    url: str
    auth_context: AuthContext
    metric: str
    value_ms: float
    mean_ms: float
    stddev_ms: float
    z_score: float


class GraphMetrics(BaseModel):
    """Graph-level coverage and structure metrics."""

    total_nodes: int = 0
    total_edges: int = 0
    orphan_nodes: list[str] = Field(default_factory=list)
    dead_end_nodes: list[str] = Field(default_factory=list)
    unreachable_nodes: list[str] = Field(default_factory=list)
    strongly_connected_components: int = 0
    cyclomatic_complexity: int = 0
    max_depth: int = 0
    edge_coverage: float = 0.0


class PrimePath(BaseModel):
    """A prime path through the graph (loop-bounded)."""

    path: list[str]
    length: int
    contains_loop: bool = False


class ComplianceControlSummary(BaseModel):
    """Summary of a single compliance control's test status."""

    standard: str
    standard_name: str
    control_id: str
    control_name: str
    testable: str
    finding_count: int = 0
    max_severity: str = ""
    manual_notes: str = ""


class ComplianceSummary(BaseModel):
    """Aggregate compliance posture across all enabled standards."""

    standards_checked: list[str] = Field(default_factory=list)
    total_violations: int = 0
    violations_by_standard: dict[str, int] = Field(default_factory=dict)
    controls: list[ComplianceControlSummary] = Field(default_factory=list)
    untestable_controls: list[ComplianceControlSummary] = Field(default_factory=list)


class SourceAnalysisResult(BaseModel):
    """Static/source scan output for repository analysis."""

    root_path: str = ""
    scanned_files: int = 0
    skipped_files: int = 0
    total_lines: int = 0
    findings: list[SecurityFinding] = Field(default_factory=list)


class RuntimeCanaryObservation(BaseModel):
    """One runtime canary input probe observation."""

    method: str = "GET"
    url: str = ""
    input_name: str = ""
    source_url: str = ""
    source_kind: str = ""  # link_query or form_get
    status_code: int | None = None
    reflected: bool = False
    reflection_contexts: list[str] = Field(default_factory=list)
    redirected: bool = False
    location: str = ""
    error: str = ""


class RuntimeCanaryResult(BaseModel):
    """Runtime canary probe output for live input analysis."""

    target_url: str = ""
    canary_prefix: str = ""
    discovered_inputs: int = 0
    requests_sent: int = 0
    skipped_inputs: int = 0
    observations: list[RuntimeCanaryObservation] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Results from Phase 3 graph analysis."""

    graph_metrics: GraphMetrics = Field(default_factory=GraphMetrics)
    broken_links: list[BrokenLink] = Field(default_factory=list)
    auth_violations: list[AuthBoundaryViolation] = Field(default_factory=list)
    timing_outliers: list[TimingOutlier] = Field(default_factory=list)
    prime_paths: list[PrimePath] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    compliance: ComplianceSummary | None = None


# ---- Run ----


def _make_run_id() -> str:
    now = datetime.now(timezone.utc)
    return f"{now.strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:8]}"


class PhaseStatus(BaseModel):
    """Status of a single phase execution."""

    phase: Literal["map", "capture", "analyze", "report", "explore", "advocate", "source_scan", "runtime_probe"]
    status: Literal["pending", "running", "completed", "failed"] = "pending"
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: float | None = None
    error: str | None = None


class CostSummary(BaseModel):
    """LLM cost tracking for the explore phase."""

    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    by_provider: dict = Field(default_factory=dict)


class Run(BaseModel):
    """A complete webprobe run. Top-level aggregation unit."""

    schema_version: str = SCHEMA_VERSION
    run_id: str = Field(default_factory=_make_run_id)
    url: str = ""
    started_at: str = ""
    completed_at: str | None = None
    config_snapshot: dict = Field(default_factory=dict)
    phases: list[PhaseStatus] = Field(default_factory=list)
    graph: SiteGraph = Field(default_factory=SiteGraph)
    analysis: AnalysisResult | None = None
    source_analysis: SourceAnalysisResult | None = None
    runtime_canary: RuntimeCanaryResult | None = None
    explore_cost: CostSummary | None = None
    advocate_cost: CostSummary | None = None


# ---- Diff ----


class NodeDiff(BaseModel):
    url: str
    change: Literal["added", "removed", "changed"]
    details: dict = Field(default_factory=dict)


class RunDiff(BaseModel):
    """Comparison between two runs."""

    run_a_id: str
    run_b_id: str
    nodes_added: list[str] = Field(default_factory=list)
    nodes_removed: list[str] = Field(default_factory=list)
    edges_added: list[Edge] = Field(default_factory=list)
    edges_removed: list[Edge] = Field(default_factory=list)
    status_changes: list[NodeDiff] = Field(default_factory=list)
    timing_changes: list[NodeDiff] = Field(default_factory=list)
    new_broken_links: list[BrokenLink] = Field(default_factory=list)
    resolved_broken_links: list[BrokenLink] = Field(default_factory=list)
    new_auth_violations: list[AuthBoundaryViolation] = Field(default_factory=list)
    resolved_auth_violations: list[AuthBoundaryViolation] = Field(default_factory=list)


# =====================================================================
# Audit pipeline models (added in schema v1.3 — CA001-CA014, CA022)
# =====================================================================
#
# These models implement the unified CheckResult schema across all 9 audit
# dimensions, the canonical Artifact store contract, structured Fix
# recommendations, and the per-dimension Scorecard. See docs/AUDIT_DIMENSIONS.md
# for the full architectural rationale and per-dimension check inventories.


# ---- Audit enums ----


class DimensionId(str, Enum):
    """The 9 audit dimensions per docs/AUDIT_DIMENSIONS.md."""

    discoverability = "discoverability"
    bot_access = "bot_access"
    agent_surface = "agent_surface"
    api_surface = "api_surface"
    structured_data = "structured_data"
    agentic_commerce = "agentic_commerce"
    public_facing_signals = "public_facing_signals"
    accessibility = "accessibility"
    general_security = "general_security"


class CheckStatus(str, Enum):
    """Trinary plus skipped — never collapse to a boolean (CA002)."""

    pass_ = "PASS"
    fail = "FAIL"
    not_detected = "NOT_DETECTED"
    skipped = "SKIPPED"


class CheckSeverity(str, Enum):
    """Drives prioritization in reports and fix-prompt copy. Orthogonal to weight (CA011)."""

    critical = "critical"
    warning = "warning"
    suggestion = "suggestion"
    info = "info"


class CheckMode(str, Enum):
    """Drives scheduler scheduling and mechanical-only SKIPPED behavior (CA006, CA007)."""

    mechanical = "mechanical"
    llm = "llm"
    hybrid = "hybrid"
    runtime = "runtime"


class ArtifactType(str, Enum):
    """The shape of payload stored in the canonical Artifact store (CA003)."""

    robots_txt = "robots_txt"
    sitemap = "sitemap"
    openapi = "openapi"
    json_ld = "json_ld"
    http_response = "http_response"
    dom = "dom"
    well_known = "well_known"
    screenshot = "screenshot"
    meta_tags = "meta_tags"


class CaptureStatus(str, Enum):
    """Capture outcome for an Artifact. Non-ok values drive NOT_DETECTED on dependent checks (CA004)."""

    ok = "ok"
    http_error = "http_error"
    network_error = "network_error"
    timeout = "timeout"
    not_found = "not_found"
    parse_error = "parse_error"


class FixActionType(str, Enum):
    """Structured remediation kinds (CA008). Webprobe never applies fixes (CA009) — these are emitted only."""

    add_meta_tag = "add_meta_tag"
    modify_robots_rule = "modify_robots_rule"
    add_robots_directive = "add_robots_directive"
    add_jsonld_block = "add_jsonld_block"
    add_well_known_resource = "add_well_known_resource"
    add_response_header = "add_response_header"
    modify_response_header = "modify_response_header"
    fix_status_code = "fix_status_code"
    rename_field = "rename_field"
    add_pagination_field = "add_pagination_field"
    add_id_prefix = "add_id_prefix"
    add_link_header = "add_link_header"
    set_cookie_attribute = "set_cookie_attribute"
    update_csp_directive = "update_csp_directive"
    other = "other"


class ScorecardBand(str, Enum):
    """Per-dimension and overall band classification (CA012, CA023)."""

    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"
    L5 = "L5"


# ---- References ----


class Reference(BaseModel):
    """Pointer to a standard, RFC, or vendor doc supporting a check or fix."""

    label: str
    url: str = ""
    rfc: str = ""


# ---- Evidence (typed union; CA005) ----


class HttpExchange(BaseModel):
    """HTTP request/response evidence for a check.

    Mask redacts request/response_headers before write per CO008.
    request_body_excerpt and response_body_excerpt are bounded to keep evidence diffable.
    """

    kind: Literal["http_exchange"] = "http_exchange"
    method: str
    url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body_excerpt: str = ""
    status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_excerpt: str = ""
    elapsed_ms: float | None = None


class DomExcerpt(BaseModel):
    """A snippet of rendered DOM as evidence for a check."""

    kind: Literal["dom_excerpt"] = "dom_excerpt"
    url: str
    selector: str = ""
    html_snippet: str = ""
    screenshot_ref: str = ""  # ArtifactRef.artifact_id when available


class RuntimeProbe(BaseModel):
    """Browser-runtime observation as evidence (e.g. navigator.modelContext check)."""

    kind: Literal["runtime_probe"] = "runtime_probe"
    url: str
    action: str
    observation: dict = Field(default_factory=dict)


class ArtifactRef(BaseModel):
    """Pointer to an Artifact in the canonical store, with an excerpt for human review."""

    kind: Literal["artifact_ref"] = "artifact_ref"
    artifact_id: str
    excerpt: str = ""


# Discriminated union for evidence — one Evidence per CheckResult (CA005).
Evidence = Annotated[
    Union[HttpExchange, DomExcerpt, RuntimeProbe, ArtifactRef],
    Field(discriminator="kind"),
]


# ---- Fix (CA008, CA009) ----


class Fix(BaseModel):
    """Structured remediation recommendation. Webprobe emits; webprobe never applies."""

    action_type: FixActionType
    target: str  # File path, URL, or DOM selector
    payload: dict = Field(default_factory=dict)  # Shape depends on action_type
    summary: str  # Human-readable one-liner
    references: list[Reference] = Field(default_factory=list)


# ---- CheckResult (CA001) ----


class CheckResult(BaseModel):
    """Single check finding emitted by a dimension analyzer.

    Unified schema across all 9 dimensions. Required fields enforced via
    Pydantic. NOT_DETECTED carries a reason (CA004) such as
    "artifact_unavailable:robots_txt:http_503" or "precondition_failed:openapi_unreachable".
    Fix is required when status is FAIL or NOT_DETECTED (CA008) — exception:
    NOT_DETECTED with reason starting "artifact_unavailable:" or
    "precondition_failed:" need not include a Fix (the upstream root cause is
    the actionable item, not a per-check fix).
    """

    dimension: DimensionId
    check_id: str  # Stable across runs; format: "<dimension>.<check_slug>"
    title: str
    goal: str
    status: CheckStatus
    severity: CheckSeverity
    mode: CheckMode
    weight: float = Field(ge=0.0, le=1.0)
    evidence: Evidence
    reason: str | None = None
    fix: Fix | None = None
    references: list[Reference] = Field(default_factory=list)
    check_dependencies: list[str] = Field(default_factory=list)
    elapsed_ms: float = 0.0  # CO011 timing-everywhere

    @field_validator("check_id")
    @classmethod
    def _check_id_format(cls, v: str) -> str:
        if not v or "." not in v:
            raise ValueError("check_id must be in '<dimension>.<check_slug>' form")
        return v

    @model_validator(mode="after")
    def _reason_required_for_non_pass(self) -> "CheckResult":
        if self.status in (CheckStatus.not_detected, CheckStatus.skipped) and not self.reason:
            raise ValueError(
                f"CheckResult.reason is required when status={self.status.value} (check_id={self.check_id})"
            )
        return self

    @model_validator(mode="after")
    def _fix_required_when_actionable(self) -> "CheckResult":
        # Fix required when:
        #   - status=FAIL (always), OR
        #   - status=NOT_DETECTED AND reason is not an upstream-root-cause marker.
        if self.status == CheckStatus.fail and self.fix is None:
            raise ValueError(
                f"CheckResult.fix is required when status=FAIL (check_id={self.check_id})"
            )
        if self.status == CheckStatus.not_detected:
            reason = (self.reason or "").lower()
            is_upstream = reason.startswith("artifact_unavailable:") or reason.startswith(
                "precondition_failed:"
            )
            if not is_upstream and self.fix is None:
                raise ValueError(
                    f"CheckResult.fix is required when status=NOT_DETECTED with non-upstream reason "
                    f"(check_id={self.check_id}, reason={self.reason!r})"
                )
        return self


# ---- Artifact store models (CA003, CA004) ----


class Artifact(BaseModel):
    """A single canonical capture in the shared store.

    Capture failures are stored as Artifacts with capture_status != ok and
    capture_error populated. Dependent checks return NOT_DETECTED with reason
    derived from capture_status.
    """

    artifact_id: str = Field(default_factory=lambda: uuid4().hex)
    artifact_type: ArtifactType
    source_url: str
    capture_status: CaptureStatus = CaptureStatus.ok
    capture_error: str = ""  # Populated when capture_status != ok
    payload: dict = Field(default_factory=dict)  # Type depends on artifact_type
    raw_bytes: bytes | None = None  # Optional raw bytes for unknown/binary types
    captured_at: int = Field(
        default_factory=lambda: int(datetime.now(timezone.utc).timestamp())
    )
    elapsed_ms: float = 0.0  # CO011

    @model_validator(mode="after")
    def _error_consistency(self) -> "Artifact":
        if self.capture_status != CaptureStatus.ok and not self.capture_error:
            raise ValueError(
                f"Artifact.capture_error is required when capture_status={self.capture_status.value}"
            )
        return self


# ---- Scorecard (CA010, CA012, CA023) ----


class DimensionScore(BaseModel):
    """Per-dimension aggregate."""

    dimension: DimensionId
    subscore: float = Field(ge=0.0, le=100.0)  # Weighted sum × 100
    band: ScorecardBand
    pass_count: int = 0
    fail_count: int = 0
    not_detected_count: int = 0
    skipped_count: int = 0
    mode_partial: bool = False  # True when one or more sub-passes were SKIPPED
    weight_sum: float = 0.0  # Sum of weights of checks that ran (PASS+FAIL+NOT_DETECTED)


class Scorecard(BaseModel):
    """Per-run aggregated scorecard.

    Per-dimension subscores plus one overall band. Never a single rolled-up
    overall numeric score (CA012).
    """

    run_id: str
    schema_version: str = SCHEMA_VERSION
    target_url: str = ""
    mode: Literal["mechanical_only", "full"] = "full"
    dimensions: dict[str, DimensionScore] = Field(default_factory=dict)  # keyed by DimensionId.value
    overall_band: ScorecardBand = ScorecardBand.L1
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @model_validator(mode="after")
    def _overall_floor(self) -> "Scorecard":
        # An overall band cannot exceed any individual dimension's band.
        order = {b: i for i, b in enumerate([
            ScorecardBand.L1, ScorecardBand.L2, ScorecardBand.L3, ScorecardBand.L4, ScorecardBand.L5
        ])}
        if not self.dimensions:
            return self
        min_band = min(self.dimensions.values(), key=lambda d: order[d.band]).band
        if order[self.overall_band] > order[min_band]:
            raise ValueError(
                f"overall_band={self.overall_band.value} exceeds floor (min dimension band={min_band.value})"
            )
        return self


def validate_dimension_weights(checks: list[CheckResult]) -> dict[str, float]:
    """Validate that weights sum to ~1.0 within each dimension (CA010).

    Returns a dict of dimension -> weight_sum for diagnostics. Raises
    ValueError if any dimension's sum deviates from 1.0 by more than 1e-3.
    """
    sums: dict[str, float] = {}
    for c in checks:
        sums[c.dimension.value] = sums.get(c.dimension.value, 0.0) + c.weight
    for dim, total in sums.items():
        if not math.isclose(total, 1.0, abs_tol=1e-3):
            raise ValueError(
                f"Dimension {dim!r} weights sum to {total:.6f}, expected 1.0 (CA010)"
            )
    return sums


# ---- SecurityFinding -> CheckResult adapter (CA001 for general_security) ----


_SECURITY_SEVERITY_MAP: dict[SecuritySeverity, CheckSeverity] = {
    SecuritySeverity.critical: CheckSeverity.critical,
    SecuritySeverity.high: CheckSeverity.critical,
    SecuritySeverity.medium: CheckSeverity.warning,
    SecuritySeverity.low: CheckSeverity.suggestion,
    SecuritySeverity.info: CheckSeverity.info,
}


def security_finding_to_check_result(
    finding: SecurityFinding,
    *,
    weight: float,
    fix: Fix | None = None,
    elapsed_ms: float = 0.0,
) -> CheckResult:
    """Adapt a SecurityFinding (Phase 3 output) to a CheckResult under
    dimension=general_security with mode=mechanical and HttpExchange evidence.

    The adapter is the v1 path for unifying security output under the new
    CheckResult schema (CA001) without rewriting all 15 security submodules to
    dual-emit. Each finding becomes one CheckResult with status=FAIL.
    Per-submodule deeper migration (rich Fix payloads, NOT_DETECTED for
    affirmative absence checks) is a follow-up block.
    """
    # Slugify category+title for a stable check_id.
    slug_source = f"{finding.category.value}.{finding.title}".lower()
    slug = "".join(c if c.isalnum() else "_" for c in slug_source).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    check_id = f"general_security.{slug}"

    evidence_body = finding.evidence or finding.detail or finding.title
    evidence = HttpExchange(
        method="GET",
        url=finding.url,
        response_body_excerpt=evidence_body[:500],
    )

    severity = _SECURITY_SEVERITY_MAP.get(finding.severity, CheckSeverity.warning)

    # SecurityFindings always represent a real failure of a check. The adapter
    # produces status=FAIL, which means a Fix is required — a generic placeholder
    # Fix is supplied when the caller doesn't pass one. Per-check Fixes will be
    # supplied as the deeper migration progresses.
    if fix is None:
        fix = Fix(
            action_type=FixActionType.other,
            target=finding.url,
            payload={"category": finding.category.value, "detail": finding.detail},
            summary=f"Address: {finding.title}",
        )

    return CheckResult(
        dimension=DimensionId.general_security,
        check_id=check_id,
        title=finding.title,
        goal=f"Detect {finding.category.value} issues on the response",
        status=CheckStatus.fail,
        severity=severity,
        mode=CheckMode.mechanical,
        weight=weight,
        evidence=evidence,
        fix=fix,
        elapsed_ms=elapsed_ms,
    )
