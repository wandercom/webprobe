"""Compliance mapping engine -- annotates SecurityFindings with standard violations."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from webprobe.models import (
    ComplianceControlSummary,
    ComplianceSummary,
    ComplianceViolation,
    SecurityFinding,
)

logger = logging.getLogger(__name__)

_DEFAULT_YAML = Path(__file__).parent / "compliance_standards.yaml"

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_SUPPORTED_MATCHER_FIELDS = {"category", "title_pattern"}
SOURCE_METADATA_IGNORED_REASON = (
    "source_path/source_line/source_column/rule_id/confidence/source_context "
    "are evidence metadata; compliance mapping v1 intentionally matches only "
    "category and title_pattern until source-aware control selectors are added."
)


def load_mappings(
    path: str | Path | None = None,
    custom_path: str | Path = "",
) -> dict:
    """Load compliance standard mappings from YAML.

    Parameters
    ----------
    path:
        Path to the primary mappings file.  Defaults to
        ``compliance_standards.yaml`` in the same directory as this module.
    custom_path:
        Optional path to a supplementary YAML file whose standards are
        merged on top of the primary mappings (additive -- new standards
        are added, existing ones are replaced).

    Returns
    -------
    dict
        Parsed YAML structure with a ``standards`` key.
    """
    yaml_path = Path(path) if path else _DEFAULT_YAML

    try:
        with open(yaml_path, "r") as fh:
            mappings = yaml.safe_load(fh)
    except Exception as exc:
        logger.warning("Failed to load compliance mappings from %s: %s", yaml_path, exc)
        return {"schema_version": "1.0", "standards": {}}

    if not isinstance(mappings, dict) or "standards" not in mappings:
        logger.warning("Compliance mappings file %s has unexpected structure", yaml_path)
        return {"schema_version": "1.0", "standards": {}}

    # Merge custom mappings if provided
    if custom_path:
        custom = Path(custom_path)
        if custom.exists():
            try:
                with open(custom, "r") as fh:
                    custom_data = yaml.safe_load(fh)
                if isinstance(custom_data, dict) and "standards" in custom_data:
                    mappings["standards"].update(custom_data["standards"])
                    logger.info(
                        "Merged %d custom standard(s) from %s",
                        len(custom_data["standards"]),
                        custom,
                    )
            except Exception as exc:
                logger.warning("Failed to load custom mappings from %s: %s", custom, exc)

    return mappings


def _matches_finding(finding: SecurityFinding, matcher: dict) -> bool:
    """Return True if *finding* matches a single control matcher entry.

    A matcher has a required ``category`` (compared against
    ``finding.category.value``) and an optional ``title_pattern`` (regex
    matched against ``finding.title``).
    """
    # Explicit C007 handling: source-only fields may be present on static
    # findings, but v1 compliance matchers ignore them for the reason captured
    # in SOURCE_METADATA_IGNORED_REASON.
    _ = SOURCE_METADATA_IGNORED_REASON

    matcher_category = matcher.get("category", "")
    if finding.category.value != matcher_category:
        return False

    title_pattern = matcher.get("title_pattern")
    if title_pattern:
        try:
            if not re.search(title_pattern, finding.title, re.IGNORECASE):
                return False
        except re.error as exc:
            logger.warning("Invalid regex in compliance matcher: %s -- %s", title_pattern, exc)
            return False

    return True


def _unsupported_matcher_fields(matcher: dict) -> list[str]:
    """Return matcher keys ignored by v1 compliance matching."""
    return sorted(set(matcher) - _SUPPORTED_MATCHER_FIELDS)


def _worse_severity(current: str, candidate: str) -> str:
    """Return whichever severity is worse (lower ordinal number)."""
    cur = _SEVERITY_ORDER.get(current, 999)
    cand = _SEVERITY_ORDER.get(candidate, 999)
    return current if cur <= cand else candidate


def annotate_findings(
    findings: list[SecurityFinding],
    mappings: dict,
    enabled_standards: list[str] | None = None,
) -> ComplianceSummary:
    """Annotate findings with compliance violations and build a summary.

    For each enabled standard, each control's ``finding_matchers`` are
    tested against every finding.  Matched findings get a
    :class:`ComplianceViolation` appended to their
    ``compliance_violations`` list (duplicates avoided).  The function
    returns a :class:`ComplianceSummary` aggregating all results.

    Parameters
    ----------
    findings:
        The list of :class:`SecurityFinding` objects (mutated in place --
        ``compliance_violations`` are appended).
    mappings:
        The parsed YAML dict returned by :func:`load_mappings`.
    enabled_standards:
        Standard keys to evaluate.  ``None`` means all standards in the
        mappings file.

    Returns
    -------
    ComplianceSummary
    """
    standards = mappings.get("standards", {})
    if enabled_standards is not None:
        standards = {k: v for k, v in standards.items() if k in enabled_standards}

    standards_checked: list[str] = sorted(standards.keys())
    violations_by_standard: dict[str, int] = {}
    controls: list[ComplianceControlSummary] = []
    untestable_controls: list[ComplianceControlSummary] = []

    for std_key, std_def in standards.items():
        std_name = std_def.get("name", std_key)
        std_violation_count = 0

        for control in std_def.get("controls", []):
            ctrl_id = control.get("id", "")
            ctrl_name = control.get("name", "")
            # YAML parses bare yes/no as booleans; normalise to strings.
            raw_testable = control.get("testable", "yes")
            if raw_testable is True:
                testable = "yes"
            elif raw_testable is False:
                testable = "no"
            else:
                testable = str(raw_testable)
            manual_notes = control.get("manual_notes", "")
            matchers = control.get("finding_matchers", [])

            # Track per-control metrics
            finding_count = 0
            max_severity = ""

            # Build a set of (finding_id) that already have this violation
            # to avoid duplicates.  We use id() since findings are mutable
            # objects in a list.
            seen_finding_ids: set[int] = set()

            if testable != "no":
                for finding in findings:
                    for matcher in matchers:
                        unsupported = _unsupported_matcher_fields(matcher)
                        if unsupported:
                            logger.info(
                                "Ignoring unsupported compliance matcher fields %s for %s:%s. Reason: %s",
                                unsupported,
                                std_key,
                                ctrl_id,
                                SOURCE_METADATA_IGNORED_REASON,
                            )
                        if _matches_finding(finding, matcher):
                            fid = id(finding)
                            if fid not in seen_finding_ids:
                                seen_finding_ids.add(fid)

                                # Avoid duplicate violations on the same
                                # finding for the same standard+control
                                already = any(
                                    v.standard == std_key and v.control_id == ctrl_id
                                    for v in finding.compliance_violations
                                )
                                if not already:
                                    finding.compliance_violations.append(
                                        ComplianceViolation(
                                            standard=std_key,
                                            standard_name=std_name,
                                            control_id=ctrl_id,
                                            control_name=ctrl_name,
                                            testable=testable,
                                        )
                                    )

                                finding_count += 1
                                sev = finding.severity.value
                                if not max_severity:
                                    max_severity = sev
                                else:
                                    max_severity = _worse_severity(max_severity, sev)

                            # One matcher match is enough per finding
                            break

            std_violation_count += finding_count

            summary = ComplianceControlSummary(
                standard=std_key,
                standard_name=std_name,
                control_id=ctrl_id,
                control_name=ctrl_name,
                testable=testable,
                finding_count=finding_count,
                max_severity=max_severity,
                manual_notes=manual_notes,
            )

            if testable == "no":
                untestable_controls.append(summary)
            elif testable == "partial":
                controls.append(summary)
                untestable_controls.append(summary)
            else:
                # testable == "yes"
                controls.append(summary)

        violations_by_standard[std_key] = std_violation_count

    total_violations = sum(violations_by_standard.values())

    return ComplianceSummary(
        standards_checked=standards_checked,
        total_violations=total_violations,
        violations_by_standard=violations_by_standard,
        controls=controls,
        untestable_controls=untestable_controls,
    )
