"""Runtime canary input probing.

This module sends harmless unique marker values through discovered GET inputs
and classifies how the application reflects or reacts to them. It is intentionally
bounded: no destructive payloads, no POST mutation by default, and no attempt to
exploit a finding.
"""

from __future__ import annotations

import asyncio
import html
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse
from uuid import uuid4

import aiohttp

from webprobe.config import RuntimeCanaryConfig, WebprobeConfig
from webprobe.models import (
    AuthContext,
    FormInfo,
    PhaseStatus,
    RuntimeCanaryObservation,
    RuntimeCanaryResult,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    SiteGraph,
)


SKIP_INPUT_NAMES = {
    "csrf", "_csrf", "csrf_token", "_token", "__requestverificationtoken",
    "authenticity_token", "password", "passwd", "pwd",
}

SKIP_INPUT_TYPES = {
    "password", "file", "submit", "button", "reset", "image",
}

ERROR_PATTERNS = (
    "traceback (most recent call last)",
    "stack trace:",
    "unhandled exception",
    "you have an error in your sql syntax",
    "sqlstate[",
    "templatesyntaxerror",
    "command not found",
)


@dataclass(frozen=True)
class CanaryCandidate:
    method: str
    url: str
    input_name: str
    source_url: str
    source_kind: str
    auth_context: AuthContext


@dataclass(frozen=True)
class CanaryResponse:
    status_code: int | None
    headers: dict[str, str]
    body: str
    final_url: str = ""
    error: str = ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _same_origin(url: str, origin: str) -> bool:
    if not origin:
        return True
    return _origin(url) == origin


def _input_allowed(name: str, input_type: str = "") -> bool:
    lower_name = name.strip().lower()
    lower_type = input_type.strip().lower()
    if not lower_name:
        return False
    if lower_name in SKIP_INPUT_NAMES:
        return False
    if "csrf" in lower_name or lower_name.endswith("_token"):
        return False
    if lower_type in SKIP_INPUT_TYPES:
        return False
    return True


def _form_inputs(form: FormInfo) -> Iterable[str]:
    for idx, name in enumerate(form.input_names):
        input_type = form.input_types[idx] if idx < len(form.input_types) else ""
        if _input_allowed(name, input_type):
            yield name


def _candidate_url_with_canary(url: str, input_name: str, canary: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    next_query: list[tuple[str, str]] = []
    for key, value in query:
        if key == input_name:
            next_query.append((key, canary))
            replaced = True
        else:
            next_query.append((key, value))
    if not replaced:
        next_query.append((input_name, canary))
    return urlunparse(parsed._replace(query=urlencode(next_query, doseq=True)))


def discover_canary_candidates(
    graph: SiteGraph,
    config: RuntimeCanaryConfig | None = None,
) -> list[CanaryCandidate]:
    """Discover safe runtime canary candidates from captured links and GET forms."""
    cfg = config or RuntimeCanaryConfig()
    allowed_methods = {method.upper() for method in cfg.methods}
    origin = _origin(graph.root_url or (graph.seed_urls[0] if graph.seed_urls else ""))
    candidates: list[CanaryCandidate] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    def add_candidate(candidate: CanaryCandidate) -> None:
        if not _same_origin(candidate.url, origin):
            return
        key = (
            candidate.method,
            candidate.url,
            candidate.input_name,
            candidate.source_kind,
            candidate.auth_context.value,
        )
        if key in seen:
            return
        seen.add(key)
        candidates.append(candidate)

    for node in graph.nodes.values():
        page_urls = [node.id]
        for capture in node.captures:
            if cfg.include_links:
                page_urls.extend(capture.outgoing_links)
            for url in page_urls:
                parsed = urlparse(url)
                if not parsed.query:
                    continue
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    if _input_allowed(key):
                        add_candidate(CanaryCandidate(
                            method="GET",
                            url=url,
                            input_name=key,
                            source_url=node.id,
                            source_kind="link_query",
                            auth_context=capture.auth_context,
                        ))

            if cfg.include_get_forms and "GET" in allowed_methods:
                for form in capture.forms:
                    if form.method.upper() != "GET":
                        continue
                    action_url = urljoin(node.id, form.action or node.id)
                    for input_name in _form_inputs(form):
                        add_candidate(CanaryCandidate(
                            method="GET",
                            url=action_url,
                            input_name=input_name,
                            source_url=node.id,
                            source_kind="form_get",
                            auth_context=capture.auth_context,
                        ))

    return candidates[:cfg.max_inputs]


def _auth_headers(config: WebprobeConfig, auth_context: AuthContext) -> dict[str, str]:
    headers: dict[str, str] = {"User-Agent": config.runtime_canary.user_agent, "Accept": "*/*"}
    if auth_context != AuthContext.authenticated:
        return headers

    auth = config.auth
    if auth.method == "bearer" and auth.bearer_token:
        headers["Authorization"] = f"Bearer {auth.bearer_token}"
    elif auth.method == "header" and auth.header_name and auth.header_value:
        headers[auth.header_name] = auth.header_value
    elif auth.method == "cookie" and auth.cookie_name and auth.cookie_value:
        headers["Cookie"] = f"{auth.cookie_name}={auth.cookie_value}"
    return headers


async def _fetch_candidate(
    session: aiohttp.ClientSession,
    candidate: CanaryCandidate,
    canary: str,
    timeout_ms: int,
) -> CanaryResponse:
    probe_url = _candidate_url_with_canary(candidate.url, candidate.input_name, canary)
    try:
        async with session.get(
            probe_url,
            timeout=aiohttp.ClientTimeout(total=timeout_ms / 1000),
            allow_redirects=False,
        ) as response:
            body = await response.text(errors="replace")
            return CanaryResponse(
                status_code=response.status,
                headers={k.lower(): v for k, v in response.headers.items()},
                body=body[:200_000],
                final_url=str(response.url),
            )
    except asyncio.TimeoutError:
        return CanaryResponse(status_code=None, headers={}, body="", error="timeout")
    except Exception as exc:
        return CanaryResponse(status_code=None, headers={}, body="", error=f"{type(exc).__name__}: {exc}")


def _contains_token(text: str, canary: str) -> bool:
    token = canary.split("_lt_gt_amp_quote", 1)[0]
    return token in text or canary in text


def classify_canary_response(
    candidate: CanaryCandidate,
    canary: str,
    response: CanaryResponse,
) -> tuple[RuntimeCanaryObservation, list[SecurityFinding]]:
    """Classify one canary response into an observation and findings."""
    probe_url = _candidate_url_with_canary(candidate.url, candidate.input_name, canary)
    body = response.body or ""
    body_lower = body.lower()
    content_type = response.headers.get("content-type", "")
    location = response.headers.get("location", "")
    token = canary.split("_lt_gt_amp_quote", 1)[0]
    escaped = html.escape(canary, quote=True)
    encoded = quote(canary, safe="")

    contexts: list[str] = []
    if canary in body:
        contexts.append("raw")
    if escaped in body:
        contexts.append("html_escaped")
    if encoded in body:
        contexts.append("url_encoded")
    if token in body:
        if "<script" in body_lower:
            for script_block in body_lower.split("<script")[1:]:
                segment = script_block.split("</script>", 1)[0]
                if token.lower() in segment:
                    contexts.append("script")
                    break
        for tag_fragment in body.split("<")[1:]:
            tag = tag_fragment.split(">", 1)[0]
            if token in tag:
                contexts.append("html_attribute_or_tag")
                break
        if "json" in content_type.lower():
            contexts.append("json")
        elif not contexts:
            contexts.append("body")

    redirected = bool(location) and _contains_token(location, canary)
    if redirected:
        contexts.append("redirect_location")

    observation = RuntimeCanaryObservation(
        method=candidate.method,
        url=probe_url,
        input_name=candidate.input_name,
        source_url=candidate.source_url,
        source_kind=candidate.source_kind,
        status_code=response.status_code,
        reflected=bool(contexts),
        reflection_contexts=sorted(set(contexts)),
        redirected=redirected,
        location=location[:300],
        error=response.error,
    )

    findings: list[SecurityFinding] = []
    evidence_base = (
        f"{candidate.method} {probe_url} input={candidate.input_name} "
        f"status={response.status_code or 'error'}"
    )

    if response.status_code is not None and response.status_code >= 500:
        findings.append(SecurityFinding(
            category=SecurityCategory.injection,
            severity=SecuritySeverity.high,
            title="Canary input triggered server error",
            detail="A harmless unique input canary produced a 5xx response. Review parser, validation, and error handling for this input.",
            evidence=evidence_base,
            url=probe_url,
            auth_context=candidate.auth_context,
            rule_id="runtime.canary.server_error",
            confidence="medium",
        ))
    elif any(pattern in body_lower for pattern in ERROR_PATTERNS):
        findings.append(SecurityFinding(
            category=SecurityCategory.injection,
            severity=SecuritySeverity.medium,
            title="Canary input exposed parser or exception details",
            detail="A harmless unique input canary response contained server/parser error text.",
            evidence=evidence_base,
            url=probe_url,
            auth_context=candidate.auth_context,
            rule_id="runtime.canary.parser_error_text",
            confidence="medium",
        ))

    if redirected:
        findings.append(SecurityFinding(
            category=SecurityCategory.auth_session,
            severity=SecuritySeverity.medium,
            title="Canary input influenced redirect location",
            detail="A harmless unique input canary appeared in a redirect Location header. Review redirect allow-listing and return URL validation.",
            evidence=f"{evidence_base}; Location: {location[:180]}",
            url=probe_url,
            auth_context=candidate.auth_context,
            rule_id="runtime.canary.redirect_influence",
            confidence="high",
        ))

    if "script" in contexts:
        findings.append(SecurityFinding(
            category=SecurityCategory.xss,
            severity=SecuritySeverity.high,
            title="Canary reflected inside script context",
            detail="A harmless unique input canary was reflected inside a script block. Review JavaScript string encoding and templating boundaries.",
            evidence=evidence_base,
            url=probe_url,
            auth_context=candidate.auth_context,
            rule_id="runtime.canary.script_reflection",
            confidence="high",
        ))
    if "html_attribute_or_tag" in contexts:
        findings.append(SecurityFinding(
            category=SecurityCategory.xss,
            severity=SecuritySeverity.medium,
            title="Canary reflected inside HTML tag or attribute context",
            detail="A harmless unique input canary was reflected inside an HTML tag/attribute context. Review attribute encoding and templating boundaries.",
            evidence=evidence_base,
            url=probe_url,
            auth_context=candidate.auth_context,
            rule_id="runtime.canary.attribute_reflection",
            confidence="medium",
        ))
    if "raw" in contexts and "script" not in contexts and "html_attribute_or_tag" not in contexts:
        findings.append(SecurityFinding(
            category=SecurityCategory.xss,
            severity=SecuritySeverity.medium,
            title="Canary reflected without HTML escaping",
            detail="A harmless unique input canary containing delimiter characters was reflected raw in the response body.",
            evidence=evidence_base,
            url=probe_url,
            auth_context=candidate.auth_context,
            rule_id="runtime.canary.raw_reflection",
            confidence="medium",
        ))
    elif "json" in contexts:
        findings.append(SecurityFinding(
            category=SecurityCategory.information_disclosure,
            severity=SecuritySeverity.info,
            title="Canary reflected in JSON response",
            detail="A harmless unique input canary was reflected in a JSON response. This may be expected for search/filter APIs but is useful for follow-up source correlation.",
            evidence=evidence_base,
            url=probe_url,
            auth_context=candidate.auth_context,
            rule_id="runtime.canary.json_reflection",
            confidence="low",
        ))

    return observation, findings


async def probe_runtime_canaries(
    graph: SiteGraph,
    config: WebprobeConfig,
) -> tuple[RuntimeCanaryResult, PhaseStatus]:
    """Run safe runtime canary probes against a captured site graph."""
    phase = PhaseStatus(phase="runtime_probe", status="running", started_at=_now_iso())
    start = time.monotonic()
    cfg = config.runtime_canary
    candidates = discover_canary_candidates(graph, cfg)
    observations: list[RuntimeCanaryObservation] = []
    findings: list[SecurityFinding] = []
    prefix = f"{cfg.canary_prefix}_{uuid4().hex[:10]}"
    skipped_inputs = 0

    try:
        sem = asyncio.Semaphore(cfg.concurrency)

        async def probe_one(idx: int, candidate: CanaryCandidate) -> None:
            nonlocal skipped_inputs
            if candidate.auth_context == AuthContext.authenticated and config.auth.method == "localStorage":
                skipped_inputs += 1
                return
            canary = f"{prefix}_{idx}_lt_gt_amp_quote_<>&\"'"
            headers = _auth_headers(config, candidate.auth_context)
            async with sem:
                async with aiohttp.ClientSession(headers=headers) as session:
                    response = await _fetch_candidate(session, candidate, canary, cfg.timeout_ms)
            observation, new_findings = classify_canary_response(candidate, canary, response)
            observations.append(observation)
            findings.extend(new_findings)

        await asyncio.gather(*(probe_one(idx, candidate) for idx, candidate in enumerate(candidates, start=1)))

        result = RuntimeCanaryResult(
            target_url=graph.root_url or (graph.seed_urls[0] if graph.seed_urls else ""),
            canary_prefix=prefix,
            discovered_inputs=len(candidates),
            requests_sent=len(observations),
            skipped_inputs=skipped_inputs,
            observations=observations,
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


def probe_runtime_canaries_sync(
    graph: SiteGraph,
    config: WebprobeConfig,
) -> tuple[RuntimeCanaryResult, PhaseStatus]:
    """Synchronous wrapper for CLI subcommands."""
    return asyncio.run(probe_runtime_canaries(graph, config))
