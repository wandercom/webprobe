"""Repository/source analysis for WebProbe.

The first implementation is deterministic and evidence-oriented: it scans text
files for secrets, weak crypto/hash use, injection-prone source/sink patterns,
authorization anti-patterns, risky config, and AI prompt-injection surfaces.
It deliberately emits reviewable findings rather than claiming full semantic
SAST coverage.
"""

from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from webprobe.config import SourceAnalysisConfig
from webprobe.models import (
    AuthContext,
    PhaseStatus,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    SourceAnalysisResult,
)


TEXT_EXTENSIONS = {
    ".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".kts", ".rb", ".php", ".cs",
    ".swift", ".scala", ".sql", ".sh", ".bash", ".zsh", ".ps1",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".example", ".dockerfile", ".md", ".txt",
}

NAMED_TEXT_FILES = {
    "Dockerfile", "Containerfile", "Procfile", "Makefile",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pyproject.toml", "poetry.lock", "requirements.txt", "Pipfile",
    "Gemfile", "Gemfile.lock", "go.mod", "go.sum", "Cargo.toml",
    "Cargo.lock", ".env", ".env.example", ".env.local",
}

TEST_PATH_PARTS = {
    "test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures",
    "example", "examples", "sample", "samples",
}


@dataclass(frozen=True)
class LineRule:
    rule_id: str
    category: SecurityCategory
    severity: SecuritySeverity
    title: str
    detail: str
    pattern: re.Pattern[str]
    confidence: str = "medium"
    test_severity: SecuritySeverity | None = None


def _compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


LINE_RULES: tuple[LineRule, ...] = (
    # Secrets and tokens
    LineRule(
        "source.secrets.aws_access_key",
        SecurityCategory.secrets,
        SecuritySeverity.critical,
        "AWS access key literal in source",
        "A source file contains a value matching the AWS access key format.",
        _compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", re.IGNORECASE),
        confidence="high",
    ),
    LineRule(
        "source.secrets.google_api_key",
        SecurityCategory.secrets,
        SecuritySeverity.high,
        "Google API key literal in source",
        "A source file contains a value matching the Google API key format.",
        _compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        confidence="high",
    ),
    LineRule(
        "source.secrets.github_token",
        SecurityCategory.secrets,
        SecuritySeverity.critical,
        "GitHub token literal in source",
        "A source file contains a value matching a GitHub token format.",
        _compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b|github_pat_[A-Za-z0-9_]{20,}\b"),
        confidence="high",
    ),
    LineRule(
        "source.secrets.openai_key",
        SecurityCategory.secrets,
        SecuritySeverity.critical,
        "OpenAI API key literal in source",
        "A source file contains a value matching an OpenAI API key format.",
        _compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{24,}\b"),
        confidence="high",
    ),
    LineRule(
        "source.secrets.slack_token",
        SecurityCategory.secrets,
        SecuritySeverity.high,
        "Slack token literal in source",
        "A source file contains a value matching a Slack token format.",
        _compile(r"\bxox[baprs]-[A-Za-z0-9\-]{20,}\b"),
        confidence="high",
    ),
    LineRule(
        "source.secrets.private_key",
        SecurityCategory.secrets,
        SecuritySeverity.critical,
        "Private key material in source",
        "A source file contains a private-key header.",
        _compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
        confidence="high",
    ),
    LineRule(
        "source.secrets.generic_assignment",
        SecurityCategory.secrets,
        SecuritySeverity.high,
        "Hardcoded secret-like assignment",
        "A password, token, key, or secret appears to be assigned a literal value.",
        _compile(r"\b(?:password|passwd|pwd|secret|secret[_-]?key|api[_-]?key|access[_-]?token|auth[_-]?token|jwt[_-]?secret|private[_-]?key)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"),
        confidence="medium",
        test_severity=SecuritySeverity.low,
    ),
    # Crypto and hashing
    LineRule(
        "source.crypto.weak_hash",
        SecurityCategory.cryptography,
        SecuritySeverity.medium,
        "Weak hash algorithm used",
        "MD5 or SHA-1 appears in source. Review whether this is security-sensitive hashing.",
        _compile(r"\b(hashlib\.(?:md5|sha1)|crypto\.createHash\(['\"](?:md5|sha1)['\"]|MessageDigest\.getInstance\(['\"]SHA-?1['\"]|Digest::(?:MD5|SHA1))"),
        confidence="medium",
        test_severity=SecuritySeverity.info,
    ),
    LineRule(
        "source.crypto.insecure_cipher_mode",
        SecurityCategory.cryptography,
        SecuritySeverity.high,
        "Insecure cipher or mode used",
        "ECB, DES, RC4, or another weak cipher pattern appears in source.",
        _compile(r"\b(AES\.MODE_ECB|aes-[0-9]+-ecb|DES\b|RC4\b|createCipher\(|createCipheriv\(['\"](?:des|rc4|aes-[0-9]+-ecb))"),
        confidence="medium",
        test_severity=SecuritySeverity.low,
    ),
    LineRule(
        "source.crypto.weak_random_security_context",
        SecurityCategory.cryptography,
        SecuritySeverity.medium,
        "Non-cryptographic randomness in security context",
        "Math.random/random.random appears near token, nonce, password, session, or secret generation.",
        _compile(r"\b(?:Math\.random|random\.random)\b.*\b(?:token|nonce|password|session|secret|csrf|otp)\b|\b(?:token|nonce|password|session|secret|csrf|otp)\b.*\b(?:Math\.random|random\.random)\b"),
        confidence="medium",
        test_severity=SecuritySeverity.info,
    ),
    LineRule(
        "source.crypto.tls_verification_disabled",
        SecurityCategory.cryptography,
        SecuritySeverity.high,
        "TLS verification disabled",
        "Source disables certificate or TLS verification.",
        _compile(r"\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?|rejectUnauthorized\s*:\s*false"),
        confidence="high",
        test_severity=SecuritySeverity.low,
    ),
    # Injection and source-to-sink risks
    LineRule(
        "source.injection.sql_interpolation",
        SecurityCategory.injection,
        SecuritySeverity.high,
        "Interpolated SQL execution",
        "A database execution call appears to build SQL with interpolation or concatenation.",
        _compile(r"\b(?:execute|executemany|query|raw)\s*\(\s*(?:f['\"`]|['\"`][^'\"`]*(?:\+|\$\{)|.*%[sd].*)"),
        confidence="medium",
        test_severity=SecuritySeverity.low,
    ),
    LineRule(
        "source.injection.shell_execution",
        SecurityCategory.injection,
        SecuritySeverity.high,
        "Shell command execution surface",
        "Source invokes shell execution. Review whether untrusted input can reach the command.",
        _compile(r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|child_process\.(?:exec|execSync)|shell_exec|System\.Diagnostics\.Process)\b"),
        confidence="medium",
        test_severity=SecuritySeverity.low,
    ),
    LineRule(
        "source.injection.shell_true",
        SecurityCategory.injection,
        SecuritySeverity.high,
        "Shell execution with shell=True",
        "A subprocess call enables shell=True, which raises command-injection risk when input is variable.",
        _compile(r"\bshell\s*=\s*True\b"),
        confidence="high",
        test_severity=SecuritySeverity.low,
    ),
    LineRule(
        "source.injection.dynamic_eval",
        SecurityCategory.injection,
        SecuritySeverity.high,
        "Dynamic code evaluation surface",
        "Dynamic eval/exec appears in source. Review whether untrusted input can reach it.",
        _compile(r"\b(?:eval|exec|Function)\s*\("),
        confidence="medium",
        test_severity=SecuritySeverity.low,
    ),
    LineRule(
        "source.injection.html_assignment",
        SecurityCategory.xss,
        SecuritySeverity.medium,
        "Raw HTML assignment surface",
        "Source assigns raw HTML or uses a dangerous HTML sink.",
        _compile(r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|v-html)\b"),
        confidence="medium",
        test_severity=SecuritySeverity.info,
    ),
    LineRule(
        "source.injection.open_redirect_surface",
        SecurityCategory.auth_session,
        SecuritySeverity.medium,
        "Redirect influenced by request input",
        "A redirect call appears near request/query/body input and may need allow-listing.",
        _compile(r"\b(?:redirect|RedirectResponse|res\.redirect|NextResponse\.redirect)\s*\(.*(?:request|req\.|params|searchParams|next|returnTo|redirect_uri|callback)"),
        confidence="medium",
        test_severity=SecuritySeverity.info,
    ),
    # Authorization/escalation
    LineRule(
        "source.authz.client_controlled_privilege",
        SecurityCategory.authorization,
        SecuritySeverity.high,
        "Client-controlled privilege field",
        "Source reads role/admin/scope/permission fields from request-controlled input.",
        _compile(r"(?:request|req)\.(?:args|form|json|body|query|params|get_json\(\)).{0,80}\b(?:role|is_admin|admin|permission|permissions|scope|scopes)\b"),
        confidence="medium",
        test_severity=SecuritySeverity.low,
    ),
    LineRule(
        "source.authz.tenant_object_from_request",
        SecurityCategory.authorization,
        SecuritySeverity.medium,
        "Tenant or object id accepted from request input",
        "Tenant, organization, user, or account identifiers are read from request input. Review owner/tenant enforcement.",
        _compile(r"(?:request|req)\.(?:args|form|json|body|query|params|get_json\(\)).{0,80}\b(?:tenant_id|org_id|organization_id|account_id|user_id|owner_id)\b"),
        confidence="low",
        test_severity=SecuritySeverity.info,
    ),
    # AI prompt-injection surfaces
    LineRule(
        "source.ai.prompt_user_interpolation",
        SecurityCategory.ai_injection,
        SecuritySeverity.medium,
        "User input interpolated into AI prompt",
        "A prompt/message appears to interpolate user-controlled input. Review instruction/data separation and tool-output handling.",
        _compile(r"\b(?:system|developer|prompt|messages?|content)\b.{0,80}(?:f['\"`].*\{[^}]*\b(?:user|input|request|req\.|params|searchParams)\b|`[^`]*\$\{[^}]*\b(?:user|input|request|req\.|params|searchParams)\b)"),
        confidence="medium",
        test_severity=SecuritySeverity.info,
    ),
    LineRule(
        "source.ai.tool_output_prompted",
        SecurityCategory.ai_injection,
        SecuritySeverity.medium,
        "Tool or retrieved content fed into AI prompt",
        "Tool, retrieval, page, or document content appears to be inserted into an AI prompt. Review prompt-injection boundaries.",
        _compile(r"\b(?:tool_output|retrieved|retrieval|document|page_text|html|scraped|search_result)\b.{0,80}\b(?:prompt|messages?|content)\b|\b(?:prompt|messages?|content)\b.{0,80}\b(?:tool_output|retrieved|retrieval|document|page_text|html|scraped|search_result)\b"),
        confidence="low",
        test_severity=SecuritySeverity.info,
    ),
    # Config and deployment
    LineRule(
        "source.config.debug_enabled",
        SecurityCategory.source_analysis,
        SecuritySeverity.medium,
        "Debug mode enabled in source or config",
        "Debug mode appears enabled. Review whether this can reach deployed environments.",
        _compile(r"\b(?:DEBUG\s*=\s*True|debug\s*=\s*true|debug\s*:\s*true|app\.run\([^)]*debug\s*=\s*True)"),
        confidence="medium",
        test_severity=SecuritySeverity.info,
    ),
    LineRule(
        "source.config.wildcard_cors",
        SecurityCategory.cors,
        SecuritySeverity.medium,
        "Wildcard CORS configured in source",
        "Source/config appears to allow wildcard CORS. Review credential use and allowed origins.",
        _compile(r"\b(?:CORS_ALLOW_ALL_ORIGINS\s*=\s*True|Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*|origin\s*:\s*['\"]\*)"),
        confidence="medium",
        test_severity=SecuritySeverity.info,
    ),
    LineRule(
        "source.config.wildcard_hosts",
        SecurityCategory.source_analysis,
        SecuritySeverity.low,
        "Wildcard host allow-list",
        "Source/config appears to allow all hosts. Review host-header protections.",
        _compile(r"\bALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]|allowedHosts\s*:\s*['\"]\*"),
        confidence="medium",
        test_severity=SecuritySeverity.info,
    ),
)

SOURCE_PATTERN = re.compile(
    r"\b(?:request\.(?:args|form|json|values|get_json)|req\.(?:query|body|params)|params|searchParams|input|user_input)\b",
    re.IGNORECASE,
)

SINK_PATTERN = re.compile(
    r"\b(?:execute|executemany|query|raw|os\.system|subprocess\.(?:run|Popen|call|check_output)|child_process\.(?:exec|execSync)|eval|exec|innerHTML|dangerouslySetInnerHTML)\b",
    re.IGNORECASE,
)

PLACEHOLDER_PATTERN = re.compile(
    r"(?:example|sample|placeholder|changeme|change_me|your_|<[^>]+>|\$\{|process\.env|os\.environ|getenv)",
    re.IGNORECASE,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_text_candidate(path: Path) -> bool:
    if path.name in NAMED_TEXT_FILES:
        return True
    lower_name = path.name.lower()
    if lower_name.startswith(".env"):
        return True
    suffixes = {suffix.lower() for suffix in path.suffixes}
    return bool(suffixes & TEXT_EXTENSIONS)


def _is_excluded(path: Path, root: Path, config: SourceAnalysisConfig) -> bool:
    rel_parts = path.relative_to(root).parts
    if any(part in config.exclude_dirs for part in rel_parts):
        return True
    rel = path.relative_to(root).as_posix()
    return any(fnmatch.fnmatch(rel, pat) for pat in config.exclude_patterns)


def _included_by_pattern(path: Path, root: Path, config: SourceAnalysisConfig) -> bool:
    if not config.include_patterns:
        return True
    rel = path.relative_to(root).as_posix()
    return any(fnmatch.fnmatch(rel, pat) for pat in config.include_patterns)


def _is_test_path(rel_path: str) -> bool:
    parts = {part.lower() for part in Path(rel_path).parts}
    return bool(parts & TEST_PATH_PARTS)


def _read_text_file(path: Path, max_file_bytes: int) -> tuple[str | None, str | None]:
    try:
        if path.stat().st_size > max_file_bytes:
            return None, "max_file_bytes"
        raw = path.read_bytes()
    except OSError as exc:
        return None, f"read_error:{exc.__class__.__name__}"

    if b"\x00" in raw[:4096]:
        return None, "binary_nul"

    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        try:
            return raw.decode("utf-8", errors="replace"), None
        except Exception as exc:  # pragma: no cover - defensive only
            return None, f"decode_error:{exc.__class__.__name__}"


def _redact_token(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "..." if value else ""
    return value[:6] + "..." + value[-4:]


def _redact_evidence(text: str) -> str:
    redacted = text.strip()
    token_patterns = [
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{24,}\b",
        r"\bxox[baprs]-[A-Za-z0-9\-]{20,}\b",
    ]
    for pattern in token_patterns:
        redacted = re.sub(pattern, lambda m: _redact_token(m.group(0)), redacted)

    assignment = re.compile(
        r"(?i)(\b(?:password|passwd|pwd|secret|secret[_-]?key|api[_-]?key|access[_-]?token|auth[_-]?token|jwt[_-]?secret|private[_-]?key)\b\s*[:=]\s*['\"])([^'\"\n]{8,})(['\"])",
    )
    redacted = assignment.sub(lambda m: m.group(1) + _redact_token(m.group(2)) + m.group(3), redacted)
    return redacted[:260]


def _severity_for_path(rule: LineRule, rel_path: str) -> SecuritySeverity:
    if _is_test_path(rel_path) and rule.test_severity is not None:
        return rule.test_severity
    return rule.severity


def _make_finding(
    *,
    rule_id: str,
    category: SecurityCategory,
    severity: SecuritySeverity,
    title: str,
    detail: str,
    root: Path,
    path: Path,
    line_no: int,
    line: str,
    confidence: str,
    extra_context: dict[str, str] | None = None,
) -> SecurityFinding:
    rel = path.relative_to(root).as_posix()
    excerpt = _redact_evidence(line)
    evidence = f"{rel}:{line_no}: {excerpt}"
    context = dict(extra_context or {})
    if _is_test_path(rel):
        context["path_context"] = "test_or_fixture"
        detail = f"{detail} Path appears to be test/example/fixture code; severity is reduced and production exposure should be verified."

    return SecurityFinding(
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence,
        url=f"source://{rel}",
        auth_context=AuthContext.anonymous,
        source_path=rel,
        source_line=line_no,
        source_excerpt=excerpt,
        rule_id=rule_id,
        confidence=confidence,
        source_context=context,
    )


def _iter_source_files(root: Path, config: SourceAnalysisConfig) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _is_excluded(path, root, config):
            continue
        if not _included_by_pattern(path, root, config):
            continue
        if _is_text_candidate(path):
            yield path


def _scan_line_rules(root: Path, path: Path, lines: list[str]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    rel = path.relative_to(root).as_posix()

    for line_no, line in enumerate(lines, start=1):
        for rule in LINE_RULES:
            if not rule.pattern.search(line):
                continue
            if rule.category == SecurityCategory.secrets and PLACEHOLDER_PATTERN.search(line):
                continue
            severity = _severity_for_path(rule, rel)
            findings.append(_make_finding(
                rule_id=rule.rule_id,
                category=rule.category,
                severity=severity,
                title=rule.title,
                detail=rule.detail,
                root=root,
                path=path,
                line_no=line_no,
                line=line,
                confidence=rule.confidence,
            ))

    return findings


def _scan_source_sink_windows(root: Path, path: Path, lines: list[str]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    rel = path.relative_to(root).as_posix()
    seen: set[tuple[int, int]] = set()

    for i, line in enumerate(lines):
        if not SOURCE_PATTERN.search(line):
            continue
        window = lines[i:min(i + 8, len(lines))]
        for offset, candidate in enumerate(window):
            if not SINK_PATTERN.search(candidate):
                continue
            sink_line_no = i + offset + 1
            key = (i + 1, sink_line_no)
            if key in seen:
                continue
            seen.add(key)
            severity = SecuritySeverity.low if _is_test_path(rel) else SecuritySeverity.high
            findings.append(_make_finding(
                rule_id="source.taint.source_to_sink_window",
                category=SecurityCategory.injection,
                severity=severity,
                title="Request-controlled input near dangerous sink",
                detail=(
                    "Heuristic source-to-sink finding: request/user input appears within "
                    "a short window of a database, shell, eval, or HTML sink. Review sanitizer, "
                    "parameterization, escaping, and authorization context."
                ),
                root=root,
                path=path,
                line_no=sink_line_no,
                line=candidate,
                confidence="medium",
                extra_context={"source_line": str(i + 1)},
            ))
            break

    return findings


def scan_repository(
    root_path: str | Path,
    config: SourceAnalysisConfig | None = None,
) -> tuple[SourceAnalysisResult, PhaseStatus]:
    """Scan a repository or source tree and return source findings."""
    cfg = config or SourceAnalysisConfig()
    root = Path(root_path).expanduser().resolve()
    phase = PhaseStatus(
        phase="source_scan",
        status="running",
        started_at=_now_iso(),
    )
    start = time.monotonic()

    scanned_files = 0
    skipped_files = 0
    total_lines = 0
    findings: list[SecurityFinding] = []

    try:
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Repository path is not a directory: {root}")

        for path in _iter_source_files(root, cfg):
            text, skip_reason = _read_text_file(path, cfg.max_file_bytes)
            if text is None:
                skipped_files += 1
                continue

            lines = text.splitlines()
            scanned_files += 1
            total_lines += len(lines)
            findings.extend(_scan_line_rules(root, path, lines))
            findings.extend(_scan_source_sink_windows(root, path, lines))

        result = SourceAnalysisResult(
            root_path=str(root),
            scanned_files=scanned_files,
            skipped_files=skipped_files,
            total_lines=total_lines,
            findings=findings,
        )
        phase.status = "completed"
        return result, phase
    except Exception as exc:
        phase.status = "failed"
        phase.error = str(exc)
        raise
    finally:
        phase.completed_at = _now_iso()
        phase.duration_ms = (time.monotonic() - start) * 1000
