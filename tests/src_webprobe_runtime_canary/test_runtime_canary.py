from __future__ import annotations

from webprobe.models import (
    AuthContext,
    DiscoveryMethod,
    FormInfo,
    Node,
    NodeCapture,
    NodeState,
    SecurityCategory,
    SiteGraph,
)
from webprobe.runtime_canary import (
    CanaryCandidate,
    CanaryResponse,
    classify_canary_response,
    discover_canary_candidates,
)


def _graph_with_inputs() -> SiteGraph:
    capture = NodeCapture(
        auth_context=AuthContext.anonymous,
        outgoing_links=[
            "https://example.test/search?q=old&page=1",
            "https://external.test/search?q=skip",
        ],
        forms=[
            FormInfo(
                action="/find",
                method="GET",
                input_names=["term", "csrf_token", "password"],
                input_types=["text", "hidden", "password"],
            )
        ],
    )
    node = Node(
        id="https://example.test/",
        state=NodeState(url="https://example.test/"),
        discovered_via=DiscoveryMethod.manual,
        captures=[capture],
    )
    return SiteGraph(
        root_url="https://example.test/",
        seed_urls=["https://example.test/"],
        nodes={node.id: node},
    )


def test_discover_canary_candidates_from_links_and_get_forms() -> None:
    candidates = discover_canary_candidates(_graph_with_inputs())

    keys = {(c.source_kind, c.url, c.input_name) for c in candidates}
    assert ("link_query", "https://example.test/search?q=old&page=1", "q") in keys
    assert ("link_query", "https://example.test/search?q=old&page=1", "page") in keys
    assert ("form_get", "https://example.test/find", "term") in keys
    assert all(c.input_name not in {"csrf_token", "password"} for c in candidates)
    assert all(c.url.startswith("https://example.test/") for c in candidates)


def test_classify_script_reflection_finding() -> None:
    candidate = CanaryCandidate(
        method="GET",
        url="https://example.test/search?q=old",
        input_name="q",
        source_url="https://example.test/",
        source_kind="link_query",
        auth_context=AuthContext.anonymous,
    )
    canary = "wp_canary_abc_1_lt_gt_amp_quote_<>&\"'"
    response = CanaryResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        body=f"<html><script>const q = '{canary}'</script></html>",
    )

    observation, findings = classify_canary_response(candidate, canary, response)

    assert observation.reflected is True
    assert "script" in observation.reflection_contexts
    assert any(f.rule_id == "runtime.canary.script_reflection" for f in findings)
    assert any(f.category == SecurityCategory.xss for f in findings)


def test_classify_redirect_influence_finding() -> None:
    candidate = CanaryCandidate(
        method="GET",
        url="https://example.test/login?next=/account",
        input_name="next",
        source_url="https://example.test/",
        source_kind="link_query",
        auth_context=AuthContext.anonymous,
    )
    canary = "wp_canary_xyz_1_lt_gt_amp_quote_<>&\"'"
    response = CanaryResponse(
        status_code=302,
        headers={"location": f"/redirected?next={canary}"},
        body="",
    )

    observation, findings = classify_canary_response(candidate, canary, response)

    assert observation.redirected is True
    assert any(f.rule_id == "runtime.canary.redirect_influence" for f in findings)
