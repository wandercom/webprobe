"""
Contract tests for webprobe data models.

This test suite verifies:
- Utility functions (_make_run_id, identity_key)
- All 6 enum types with value validation
- Simple structs (TimingData, Resource, ConsoleMessage, etc.)
- Complex nested structs (NodeCapture, Node, Edge, SiteGraph, Run)
- Analysis results and diff structures
- Serialization round-trips
- Graph invariants
- Edge cases and error handling
"""

import pytest
import re
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import Mock, patch

# Import the module under test
from src.webprobe.models import (
    AuthContext,
    DiscoveryMethod,
    ResourceType,
    ConsoleMessageLevel,
    SecuritySeverity,
    SecurityCategory,
    TimingData,
    Resource,
    ConsoleMessage,
    NodeState,
    CookieInfo,
    ResponseHeaders,
    FormInfo,
    SecurityFinding,
    NodeCapture,
    Node,
    Edge,
    SiteGraph,
    BrokenLink,
    AuthBoundaryViolation,
    TimingOutlier,
    GraphMetrics,
    PrimePath,
    AnalysisResult,
    PhaseStatus,
    CostSummary,
    Run,
    NodeDiff,
    RunDiff,
    _make_run_id,
    SCHEMA_VERSION,
)


# ============================================================================
# UTILITY FUNCTION TESTS
# ============================================================================

class TestMakeRunId:
    """Tests for _make_run_id() function."""

    def test_make_run_id_format(self):
        """Test that _make_run_id returns string matching pattern YYYYMMDDTHHmmss-[a-f0-9]{8}"""
        run_id = _make_run_id()
        
        # Check overall pattern
        pattern = r'^\d{8}T\d{6}-[a-f0-9]{8}$'
        assert re.match(pattern, run_id), f"run_id '{run_id}' does not match pattern"
        
        # Check timestamp is 15 chars (YYYYMMDDTHHmmss)
        timestamp_part = run_id.split('-')[0]
        assert len(timestamp_part) == 15, f"Timestamp part should be 15 chars, got {len(timestamp_part)}"
        
        # Check separator is dash
        assert '-' in run_id, "Should contain dash separator"
        
        # Check UUID suffix is 8 hex chars
        uuid_part = run_id.split('-')[1]
        assert len(uuid_part) == 8, f"UUID suffix should be 8 chars, got {len(uuid_part)}"
        assert all(c in '0123456789abcdef' for c in uuid_part), "UUID suffix should be lowercase hex"

    def test_make_run_id_uniqueness(self):
        """Test that _make_run_id generates unique IDs over multiple invocations"""
        run_ids = set()
        iterations = 1000
        
        for _ in range(iterations):
            run_id = _make_run_id()
            run_ids.add(run_id)
        
        # All generated IDs should be unique (no collisions)
        assert len(run_ids) == iterations, f"Expected {iterations} unique IDs, got {len(run_ids)}"

    def test_make_run_id_timestamp_utc(self):
        """Test that _make_run_id timestamp is in UTC timezone"""
        before = datetime.now(timezone.utc)
        run_id = _make_run_id()
        after = datetime.now(timezone.utc)
        
        # Extract timestamp portion
        timestamp_str = run_id.split('-')[0]
        
        # Parse timestamp (YYYYMMDDTHHmmss)
        parsed_time = datetime.strptime(timestamp_str, '%Y%m%dT%H%M%S').replace(tzinfo=timezone.utc)
        
        # Should be between before and after (truncate to seconds since run_id drops microseconds)
        before_trunc = before.replace(microsecond=0)
        assert before_trunc <= parsed_time <= after, "Timestamp should be current UTC time"


class TestIdentityKey:
    """Tests for NodeState.identity_key() method."""

    def test_identity_key_returns_url(self):
        """Test that NodeState.identity_key returns the URL"""
        url = "https://example.com"
        node_state = NodeState(url=url)
        
        assert node_state.identity_key() == url, "identity_key should return URL"

    def test_identity_key_deterministic(self):
        """Test that NodeState.identity_key returns consistent value for same URL"""
        url = "https://example.com/path"
        node_state = NodeState(url=url)
        
        # Call multiple times
        key1 = node_state.identity_key()
        key2 = node_state.identity_key()
        
        assert key1 == key2, "identity_key should be deterministic"
        
        # Should be hashable for use as dict key
        test_dict = {key1: "value"}
        assert test_dict[key2] == "value", "identity_key should be hashable"


# ============================================================================
# ENUM TESTS
# ============================================================================

class TestEnums:
    """Tests for all enum types."""

    def test_auth_context_enum_values(self):
        """Test AuthContext enum has correct values"""
        assert hasattr(AuthContext, 'anonymous'), "Should have 'anonymous' variant"
        assert hasattr(AuthContext, 'authenticated'), "Should have 'authenticated' variant"
        
        # Check exactly 2 variants
        assert len(list(AuthContext)) == 2, "Should have exactly 2 variants"

    def test_discovery_method_enum_values(self):
        """Test DiscoveryMethod enum has all expected values"""
        expected = ['sitemap', 'robots', 'crawl', 'framework', 'manual']
        
        for variant in expected:
            assert hasattr(DiscoveryMethod, variant), f"Should have '{variant}' variant"
        
        assert len(list(DiscoveryMethod)) == 5, "Should have exactly 5 variants"

    def test_resource_type_enum_values(self):
        """Test ResourceType enum has all expected values"""
        expected = ['document', 'script', 'stylesheet', 'image', 'font', 
                   'media', 'xhr', 'fetch', 'websocket', 'other']
        
        for variant in expected:
            assert hasattr(ResourceType, variant), f"Should have '{variant}' variant"
        
        assert len(list(ResourceType)) == 10, "Should have exactly 10 variants"

    def test_console_message_level_enum_values(self):
        """Test ConsoleMessageLevel enum has all expected values"""
        expected = ['log', 'warning', 'error', 'info', 'debug']
        
        for variant in expected:
            assert hasattr(ConsoleMessageLevel, variant), f"Should have '{variant}' variant"
        
        assert len(list(ConsoleMessageLevel)) == 5, "Should have exactly 5 variants"

    def test_security_severity_enum_values(self):
        """Test SecuritySeverity enum has all expected values"""
        expected = ['critical', 'high', 'medium', 'low', 'info']
        
        for variant in expected:
            assert hasattr(SecuritySeverity, variant), f"Should have '{variant}' variant"
        
        assert len(list(SecuritySeverity)) == 5, "Should have exactly 5 variants"

    def test_security_category_enum_values(self):
        """Test SecurityCategory enum has all expected values"""
        expected = ['headers', 'cookies', 'xss', 'mixed_content', 'cors',
                   'information_disclosure', 'forms', 'tls',
                   'accessibility', 'visual', 'exploration',
                   'secrets', 'cryptography', 'authorization',
                   'ai_injection', 'source_analysis']

        for variant in expected:
            assert hasattr(SecurityCategory, variant), f"Should have '{variant}' variant"

        assert len(list(SecurityCategory)) == 22, "Should have exactly 22 variants"


# ============================================================================
# SIMPLE STRUCT TESTS
# ============================================================================

class TestTimingData:
    """Tests for TimingData struct."""

    def test_timing_data_complete(self):
        """Test TimingData with all fields populated"""
        timing = TimingData(
            started_at="2024-01-15T10:30:00Z",
            duration_ms=250.5,
            ttfb_ms=120.3
        )
        
        assert timing.started_at == "2024-01-15T10:30:00Z"
        assert timing.duration_ms == 250.5
        assert timing.ttfb_ms == 120.3
        assert isinstance(timing.duration_ms, float)
        assert isinstance(timing.ttfb_ms, float)

    def test_timing_data_optional_ttfb(self):
        """Test TimingData with ttfb_ms as None"""
        timing = TimingData(
            started_at="2024-01-15T10:30:00Z",
            duration_ms=250.5,
            ttfb_ms=None
        )
        
        assert timing.ttfb_ms is None
        assert timing.started_at == "2024-01-15T10:30:00Z"
        assert timing.duration_ms == 250.5

    def test_timing_data_zero_duration(self):
        """Test TimingData with zero duration"""
        timing = TimingData(
            started_at="2024-01-15T10:30:00Z",
            duration_ms=0.0,
            ttfb_ms=0.0
        )
        
        assert timing.duration_ms == 0.0
        assert timing.ttfb_ms == 0.0


class TestResource:
    """Tests for Resource struct."""

    def test_resource_complete(self):
        """Test Resource with all fields populated"""
        timing = TimingData(started_at="2024-01-15T10:30:00Z", duration_ms=100.0, ttfb_ms=50.0)
        resource = Resource(
            url="https://example.com/script.js",
            resource_type=ResourceType.script,
            status_code=200,
            size_bytes=15000,
            timing=timing,
            mime_type="application/javascript"
        )
        
        assert resource.url == "https://example.com/script.js"
        assert resource.resource_type == ResourceType.script
        assert resource.status_code == 200
        assert resource.size_bytes == 15000
        assert resource.mime_type == "application/javascript"
        assert resource.timing == timing

    def test_resource_optional_fields_none(self):
        """Test Resource with optional fields as None"""
        resource = Resource(
            url="https://example.com/image.png",
            resource_type=ResourceType.image,
            status_code=None,
            size_bytes=None,
            timing=None,
            mime_type="image/png"
        )
        
        assert resource.status_code is None
        assert resource.size_bytes is None
        assert resource.timing is None


class TestConsoleMessage:
    """Tests for ConsoleMessage struct."""

    def test_console_message_complete(self):
        """Test ConsoleMessage with all fields"""
        msg = ConsoleMessage(
            level=ConsoleMessageLevel.error,
            text="Uncaught TypeError",
            url="https://example.com/app.js",
            line=42
        )
        
        assert msg.level == ConsoleMessageLevel.error
        assert msg.text == "Uncaught TypeError"
        assert msg.url == "https://example.com/app.js"
        assert msg.line == 42
        assert isinstance(msg.line, int)

    def test_console_message_no_line(self):
        """Test ConsoleMessage with line as None"""
        msg = ConsoleMessage(
            level=ConsoleMessageLevel.log,
            text="Debug message",
            url="https://example.com",
            line=None
        )
        
        assert msg.line is None
        assert msg.level == ConsoleMessageLevel.log
        assert msg.text == "Debug message"


class TestNodeState:
    """Tests for NodeState struct."""

    def test_node_state_simple(self):
        """Test NodeState creation with URL"""
        state = NodeState(url="https://example.com/page")
        
        assert state.url == "https://example.com/page"

    def test_url_absolute_validation(self):
        """Test handling of absolute URLs"""
        url = "https://example.com/path?query=value#fragment"
        state = NodeState(url=url)
        
        assert state.url == url

    def test_url_very_long(self):
        """Test handling of very long URLs"""
        # Create URL with 2000+ characters
        long_path = "a" * 2000
        url = f"https://example.com/{long_path}"
        state = NodeState(url=url)
        
        assert len(state.url) > 2000
        assert state.url == url


class TestCookieInfo:
    """Tests for CookieInfo struct."""

    def test_cookie_info_secure(self):
        """Test CookieInfo with secure attributes"""
        cookie = CookieInfo(
            name="session",
            domain="example.com",
            path="/",
            secure=True,
            http_only=True,
            same_site="Strict"
        )
        
        assert cookie.secure is True
        assert cookie.http_only is True
        assert cookie.same_site == "Strict"

    def test_cookie_info_insecure(self):
        """Test CookieInfo with insecure attributes"""
        cookie = CookieInfo(
            name="tracking",
            domain="example.com",
            path="/",
            secure=False,
            http_only=False,
            same_site="None"
        )
        
        assert cookie.secure is False
        assert cookie.http_only is False
        assert cookie.same_site == "None"


class TestResponseHeaders:
    """Tests for ResponseHeaders struct."""

    def test_response_headers_empty(self):
        """Test ResponseHeaders with empty dict"""
        headers = ResponseHeaders(raw={})
        
        assert headers.raw == {}
        assert isinstance(headers.raw, dict)

    def test_response_headers_populated(self):
        """Test ResponseHeaders with security headers"""
        headers = ResponseHeaders(raw={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY"
        })
        
        assert "Content-Security-Policy" in headers.raw
        assert headers.raw["X-Frame-Options"] == "DENY"


class TestFormInfo:
    """Tests for FormInfo struct."""

    def test_form_info_csrf_protected(self):
        """Test FormInfo with CSRF protection"""
        form = FormInfo(
            action="/login",
            method="POST",
            has_csrf_token=True,
            has_password_field=True,
            autocomplete_off=False
        )
        
        assert form.has_csrf_token is True
        assert form.has_password_field is True
        assert form.method == "POST"

    def test_form_info_no_csrf(self):
        """Test FormInfo without CSRF protection"""
        form = FormInfo(
            action="/search",
            method="GET",
            has_csrf_token=False,
            has_password_field=False,
            autocomplete_off=True
        )
        
        assert form.has_csrf_token is False
        assert form.method == "GET"
        assert form.autocomplete_off is True


class TestSecurityFinding:
    """Tests for SecurityFinding struct."""

    def test_security_finding_critical(self):
        """Test SecurityFinding with critical severity"""
        finding = SecurityFinding(
            category=SecurityCategory.xss,
            severity=SecuritySeverity.critical,
            title="Reflected XSS",
            detail="User input not sanitized",
            evidence="<script>alert(1)</script>",
            url="https://example.com/search",
            auth_context=AuthContext.anonymous
        )
        
        assert finding.severity == SecuritySeverity.critical
        assert finding.category == SecurityCategory.xss
        assert finding.title == "Reflected XSS"
        assert finding.evidence == "<script>alert(1)</script>"

    def test_security_finding_info(self):
        """Test SecurityFinding with info severity"""
        finding = SecurityFinding(
            category=SecurityCategory.headers,
            severity=SecuritySeverity.info,
            title="Missing header",
            detail="X-Content-Type-Options not set",
            evidence="",
            url="https://example.com",
            auth_context=AuthContext.authenticated
        )
        
        assert finding.severity == SecuritySeverity.info
        assert finding.evidence == ""


# ============================================================================
# COMPLEX STRUCT TESTS
# ============================================================================

class TestNodeCapture:
    """Tests for NodeCapture struct."""

    def test_node_capture_minimal(self):
        """Test NodeCapture with minimal fields"""
        capture = NodeCapture(
            auth_context=AuthContext.anonymous,
            http_status=None,
            timing=None,
            dom_content_loaded_ms=None,
            load_event_ms=None,
            page_title="",
            page_text="",
            resources=[],
            console_messages=[],
            outgoing_links=[],
            screenshot_path="",
            response_headers=ResponseHeaders(raw={}),
            cookies=[],
            forms=[],
            security_findings=[]
        )
        
        assert capture.http_status is None
        assert capture.resources == []
        assert capture.console_messages == []

    def test_node_capture_complete(self):
        """Test NodeCapture with all fields populated"""
        timing = TimingData(started_at="2024-01-15T10:00:00Z", duration_ms=500.0, ttfb_ms=100.0)
        resource = Resource(
            url="https://example.com/style.css",
            resource_type=ResourceType.stylesheet,
            status_code=200,
            size_bytes=5000,
            timing=None,
            mime_type="text/css"
        )
        
        capture = NodeCapture(
            auth_context=AuthContext.authenticated,
            http_status=200,
            timing=timing,
            dom_content_loaded_ms=300.0,
            load_event_ms=450.0,
            page_title="Dashboard",
            page_text="Welcome user",
            resources=[resource],
            console_messages=[],
            outgoing_links=["https://example.com/profile"],
            screenshot_path="/tmp/screenshot.png",
            response_headers=ResponseHeaders(raw={"X-Frame-Options": "SAMEORIGIN"}),
            cookies=[],
            forms=[],
            security_findings=[]
        )
        
        assert capture.http_status == 200
        assert capture.page_title == "Dashboard"
        assert len(capture.resources) == 1
        assert isinstance(capture.resources, list)

    def test_empty_collections_default(self):
        """Test that list fields default to empty lists not shared instances"""
        capture1 = NodeCapture(
            auth_context=AuthContext.anonymous,
            http_status=200,
            page_title="",
            page_text="",
            screenshot_path="",
            response_headers=ResponseHeaders(raw={})
        )
        
        capture2 = NodeCapture(
            auth_context=AuthContext.anonymous,
            http_status=200,
            page_title="",
            page_text="",
            screenshot_path="",
            response_headers=ResponseHeaders(raw={})
        )
        
        # Modify one instance's list
        capture1.resources.append(Resource(
            url="https://example.com/test.js",
            resource_type=ResourceType.script,
            status_code=200,
            size_bytes=1000,
            timing=None,
            mime_type="application/javascript"
        ))
        
        # Other instance should not be affected
        assert len(capture1.resources) == 1
        assert len(capture2.resources) == 0


class TestNode:
    """Tests for Node struct."""

    def test_node_minimal(self):
        """Test Node with minimal required fields"""
        state = NodeState(url="https://example.com")
        node = Node(
            id="node1",
            state=state,
            discovered_via=DiscoveryMethod.manual,
            requires_auth=None,
            auth_contexts_available=[],
            captures=[],
            depth=0
        )
        
        assert node.id == "node1"
        assert node.depth == 0
        assert node.requires_auth is None

    def test_node_with_captures(self):
        """Test Node with multiple captures"""
        state = NodeState(url="https://example.com/page")
        capture1 = NodeCapture(
            auth_context=AuthContext.anonymous,
            http_status=200,
            page_title="Public",
            page_text="",
            screenshot_path="",
            response_headers=ResponseHeaders(raw={})
        )
        capture2 = NodeCapture(
            auth_context=AuthContext.authenticated,
            http_status=200,
            page_title="Private",
            page_text="",
            screenshot_path="",
            response_headers=ResponseHeaders(raw={})
        )
        
        node = Node(
            id="node2",
            state=state,
            discovered_via=DiscoveryMethod.crawl,
            requires_auth=False,
            auth_contexts_available=[AuthContext.anonymous, AuthContext.authenticated],
            captures=[capture1, capture2],
            depth=2
        )
        
        assert isinstance(node.captures, list)
        assert len(node.captures) == 2
        assert len(node.auth_contexts_available) == 2

    def test_node_depth_consistency(self):
        """Test that node depth values are consistent with graph structure"""
        # Root node should have depth 0
        root_state = NodeState(url="https://example.com")
        root = Node(
            id="root",
            state=root_state,
            discovered_via=DiscoveryMethod.manual,
            requires_auth=None,
            auth_contexts_available=[],
            captures=[],
            depth=0
        )
        
        assert root.depth == 0
        
        # Child node should have depth > 0
        child_state = NodeState(url="https://example.com/page")
        child = Node(
            id="child",
            state=child_state,
            discovered_via=DiscoveryMethod.crawl,
            requires_auth=None,
            auth_contexts_available=[],
            captures=[],
            depth=1
        )
        
        assert child.depth == root.depth + 1


class TestEdge:
    """Tests for Edge struct."""

    def test_edge_verified(self):
        """Test Edge with verified link"""
        edge = Edge(
            source="node1",
            target="node2",
            link_text="Click here",
            discovered_via=DiscoveryMethod.crawl,
            auth_context=AuthContext.anonymous,
            verified=True
        )
        
        assert edge.verified is True
        assert edge.source == "node1"
        assert edge.target == "node2"

    def test_edge_unverified(self):
        """Test Edge with unverified link"""
        edge = Edge(
            source="node1",
            target="node3",
            link_text="",
            discovered_via=DiscoveryMethod.sitemap,
            auth_context=AuthContext.authenticated,
            verified=False
        )
        
        assert edge.verified is False
        assert edge.link_text == ""


class TestSiteGraph:
    """Tests for SiteGraph struct."""

    def test_site_graph_empty(self):
        """Test SiteGraph with no nodes or edges"""
        graph = SiteGraph(
            nodes={},
            edges=[],
            root_url="https://example.com",
            seed_urls=[]
        )
        
        assert graph.nodes == {}
        assert graph.edges == []
        assert isinstance(graph.nodes, dict)
        assert isinstance(graph.edges, list)

    def test_site_graph_with_data(self):
        """Test SiteGraph with nodes and edges"""
        state = NodeState(url="https://example.com")
        node = Node(
            id="node1",
            state=state,
            discovered_via=DiscoveryMethod.manual,
            requires_auth=None,
            auth_contexts_available=[],
            captures=[],
            depth=0
        )
        
        graph = SiteGraph(
            nodes={"node1": node},
            edges=[],
            root_url="https://example.com",
            seed_urls=["https://example.com"]
        )
        
        assert graph.root_url == "https://example.com"
        assert len(graph.seed_urls) == 1

    def test_edge_references_valid_nodes(self):
        """Test that edges reference nodes that exist in graph"""
        state1 = NodeState(url="https://example.com")
        node1 = Node(
            id="node1",
            state=state1,
            discovered_via=DiscoveryMethod.manual,
            requires_auth=None,
            auth_contexts_available=[],
            captures=[],
            depth=0
        )
        
        state2 = NodeState(url="https://example.com/page")
        node2 = Node(
            id="node2",
            state=state2,
            discovered_via=DiscoveryMethod.crawl,
            requires_auth=None,
            auth_contexts_available=[],
            captures=[],
            depth=1
        )
        
        edge = Edge(
            source="node1",
            target="node2",
            link_text="Link",
            discovered_via=DiscoveryMethod.crawl,
            auth_context=AuthContext.anonymous,
            verified=True
        )
        
        graph = SiteGraph(
            nodes={"node1": node1, "node2": node2},
            edges=[edge],
            root_url="https://example.com",
            seed_urls=["https://example.com"]
        )
        
        # All edge sources should exist in nodes
        for e in graph.edges:
            assert e.source in graph.nodes, f"Edge source {e.source} not in nodes"
            assert e.target in graph.nodes, f"Edge target {e.target} not in nodes"


# ============================================================================
# ANALYSIS RESULT TESTS
# ============================================================================

class TestBrokenLink:
    """Tests for BrokenLink struct."""

    def test_broken_link_with_status(self):
        """Test BrokenLink with status code"""
        broken = BrokenLink(
            source="https://example.com",
            target="https://example.com/missing",
            status_code=404,
            error="Not Found"
        )
        
        assert broken.status_code == 404
        assert broken.error == "Not Found"

    def test_broken_link_network_error(self):
        """Test BrokenLink with network error and no status"""
        broken = BrokenLink(
            source="https://example.com",
            target="https://unreachable.invalid",
            status_code=None,
            error="DNS resolution failed"
        )
        
        assert broken.status_code is None
        assert "DNS" in broken.error


class TestAuthBoundaryViolation:
    """Tests for AuthBoundaryViolation struct."""

    def test_auth_boundary_violation(self):
        """Test AuthBoundaryViolation for unprotected admin page"""
        violation = AuthBoundaryViolation(
            url="https://example.com/admin",
            expected_auth=True,
            actual_accessible_anonymous=True,
            evidence="200 OK without credentials"
        )
        
        assert violation.expected_auth is True
        assert violation.actual_accessible_anonymous is True


class TestTimingOutlier:
    """Tests for TimingOutlier struct."""

    def test_timing_outlier(self):
        """Test TimingOutlier for slow page load"""
        outlier = TimingOutlier(
            url="https://example.com/slow",
            auth_context=AuthContext.anonymous,
            metric="duration_ms",
            value_ms=5000.0,
            mean_ms=200.0,
            stddev_ms=50.0,
            z_score=96.0
        )
        
        assert outlier.z_score == 96.0
        assert outlier.value_ms > outlier.mean_ms

    def test_timing_outlier_zero_stddev(self):
        """Test TimingOutlier edge case with zero standard deviation"""
        outlier = TimingOutlier(
            url="https://example.com",
            auth_context=AuthContext.anonymous,
            metric="ttfb_ms",
            value_ms=100.0,
            mean_ms=100.0,
            stddev_ms=0.0,
            z_score=0.0
        )
        
        assert outlier.z_score == 0.0
        assert outlier.stddev_ms == 0.0


class TestGraphMetrics:
    """Tests for GraphMetrics struct."""

    def test_graph_metrics_simple(self):
        """Test GraphMetrics for simple graph"""
        metrics = GraphMetrics(
            total_nodes=10,
            total_edges=15,
            orphan_nodes=[],
            dead_end_nodes=[],
            unreachable_nodes=[],
            strongly_connected_components=1,
            cyclomatic_complexity=6,
            max_depth=5,
            edge_coverage=1.0
        )
        
        assert metrics.total_nodes == 10
        assert metrics.edge_coverage == 1.0

    def test_graph_metrics_with_issues(self):
        """Test GraphMetrics with orphan and dead-end nodes"""
        metrics = GraphMetrics(
            total_nodes=20,
            total_edges=18,
            orphan_nodes=["node1", "node2"],
            dead_end_nodes=["node3"],
            unreachable_nodes=["node4"],
            strongly_connected_components=3,
            cyclomatic_complexity=0,
            max_depth=8,
            edge_coverage=0.75
        )
        
        assert len(metrics.orphan_nodes) == 2
        assert metrics.edge_coverage < 1.0

    def test_graph_metrics_zero_nodes(self):
        """Test GraphMetrics for empty graph"""
        metrics = GraphMetrics(
            total_nodes=0,
            total_edges=0,
            orphan_nodes=[],
            dead_end_nodes=[],
            unreachable_nodes=[],
            strongly_connected_components=0,
            cyclomatic_complexity=0,
            max_depth=0,
            edge_coverage=0.0
        )
        
        assert metrics.total_nodes == 0
        assert metrics.total_edges == 0
        assert metrics.edge_coverage == 0.0


class TestPrimePath:
    """Tests for PrimePath struct."""

    def test_prime_path_no_loop(self):
        """Test PrimePath without loop"""
        path = PrimePath(
            path=["node1", "node2", "node3"],
            length=3,
            contains_loop=False
        )
        
        assert path.contains_loop is False
        assert path.length == 3

    def test_prime_path_with_loop(self):
        """Test PrimePath with loop"""
        path = PrimePath(
            path=["node1", "node2", "node1"],
            length=3,
            contains_loop=True
        )
        
        assert path.contains_loop is True
        assert "node1" in path.path


class TestAnalysisResult:
    """Tests for AnalysisResult struct."""

    def test_analysis_result_complete(self):
        """Test AnalysisResult with all findings"""
        metrics = GraphMetrics(
            total_nodes=5,
            total_edges=6,
            orphan_nodes=[],
            dead_end_nodes=[],
            unreachable_nodes=[],
            strongly_connected_components=1,
            cyclomatic_complexity=2,
            max_depth=3,
            edge_coverage=1.0
        )
        
        result = AnalysisResult(
            graph_metrics=metrics,
            broken_links=[],
            auth_violations=[],
            timing_outliers=[],
            prime_paths=[],
            security_findings=[]
        )
        
        assert isinstance(result.broken_links, list)
        assert isinstance(result.auth_violations, list)
        assert result.graph_metrics is not None

    def test_analysis_result_empty(self):
        """Test AnalysisResult with no findings"""
        metrics = GraphMetrics(
            total_nodes=0,
            total_edges=0,
            orphan_nodes=[],
            dead_end_nodes=[],
            unreachable_nodes=[],
            strongly_connected_components=0,
            cyclomatic_complexity=0,
            max_depth=0,
            edge_coverage=0.0
        )
        
        result = AnalysisResult(
            graph_metrics=metrics,
            broken_links=[],
            auth_violations=[],
            timing_outliers=[],
            prime_paths=[],
            security_findings=[]
        )
        
        assert len(result.broken_links) == 0
        assert len(result.auth_violations) == 0


# ============================================================================
# PHASE STATUS AND COST TESTS
# ============================================================================

class TestPhaseStatus:
    """Tests for PhaseStatus struct."""

    def test_phase_status_pending(self):
        """Test PhaseStatus in pending state"""
        status = PhaseStatus(
            phase="map",
            status="pending",
            started_at=None,
            completed_at=None,
            duration_ms=None,
            error=None
        )
        
        assert status.status == "pending"
        assert status.started_at is None

    def test_phase_status_completed(self):
        """Test PhaseStatus in completed state"""
        status = PhaseStatus(
            phase="capture",
            status="completed",
            started_at="2024-01-15T10:00:00Z",
            completed_at="2024-01-15T10:05:00Z",
            duration_ms=300000.0,
            error=None
        )
        
        assert status.status == "completed"
        assert status.started_at is not None
        assert status.completed_at is not None
        assert status.duration_ms > 0

    def test_phase_status_failed(self):
        """Test PhaseStatus in failed state"""
        status = PhaseStatus(
            phase="analyze",
            status="failed",
            started_at="2024-01-15T10:00:00Z",
            completed_at="2024-01-15T10:01:00Z",
            duration_ms=60000.0,
            error="Connection timeout"
        )
        
        assert status.status == "failed"
        assert status.error == "Connection timeout"


class TestCostSummary:
    """Tests for CostSummary struct."""

    def test_cost_summary_zero_cost(self):
        """Test CostSummary with zero cost"""
        cost = CostSummary(
            total_calls=0,
            total_input_tokens=0,
            total_output_tokens=0,
            total_cost_usd=0.0,
            by_provider={}
        )
        
        assert cost.total_cost_usd == 0.0
        assert cost.total_calls == 0

    def test_cost_summary_with_usage(self):
        """Test CostSummary with actual usage"""
        cost = CostSummary(
            total_calls=150,
            total_input_tokens=5000,
            total_output_tokens=3000,
            total_cost_usd=0.25,
            by_provider={"openai": {"calls": 150, "cost_usd": 0.25}}
        )
        
        assert cost.total_calls == 150
        assert "openai" in cost.by_provider


# ============================================================================
# RUN AND DIFF TESTS
# ============================================================================

class TestRun:
    """Tests for Run struct."""

    def test_run_minimal(self):
        """Test Run with minimal required fields"""
        graph = SiteGraph(
            nodes={},
            edges=[],
            root_url="https://example.com",
            seed_urls=[]
        )
        
        run = Run(
            schema_version="1.3",
            run_id="test-run-123",
            url="https://example.com",
            started_at="2024-01-15T10:00:00Z",
            completed_at=None,
            config_snapshot={},
            phases=[],
            graph=graph,
            analysis=None,
            explore_cost=None
        )
        
        assert run.schema_version == "1.3"
        assert run.run_id == "test-run-123"
        assert run.completed_at is None

    def test_run_complete(self):
        """Test Run with all phases completed"""
        graph = SiteGraph(
            nodes={},
            edges=[],
            root_url="https://example.com",
            seed_urls=["https://example.com"]
        )
        
        run = Run(
            schema_version="1.3",
            run_id="test-run-456",
            url="https://example.com",
            started_at="2024-01-15T10:00:00Z",
            completed_at="2024-01-15T11:00:00Z",
            config_snapshot={},
            phases=[],
            graph=graph,
            analysis=None,
            explore_cost=None
        )
        
        assert run.completed_at == "2024-01-15T11:00:00Z"
        assert isinstance(run.phases, list)

    def test_run_schema_version_invariant(self):
        """Test that Run defaults to SCHEMA_VERSION 1.3 (Block 1 audit expansion)."""
        # Test constant
        assert SCHEMA_VERSION == "1.3"
        
        graph = SiteGraph(
            nodes={},
            edges=[],
            root_url="https://example.com",
            seed_urls=[]
        )
        
        run = Run(
            schema_version=SCHEMA_VERSION,
            run_id="test",
            url="https://example.com",
            started_at="2024-01-15T10:00:00Z",
            config_snapshot={},
            phases=[],
            graph=graph
        )
        
        assert run.schema_version == "1.3"


class TestNodeDiff:
    """Tests for NodeDiff struct."""

    def test_node_diff_added(self):
        """Test NodeDiff for added node"""
        diff = NodeDiff(
            url="https://example.com/new",
            change="added",
            details={}
        )
        
        assert diff.change == "added"

    def test_node_diff_removed(self):
        """Test NodeDiff for removed node"""
        diff = NodeDiff(
            url="https://example.com/old",
            change="removed",
            details={}
        )
        
        assert diff.change == "removed"

    def test_node_diff_changed(self):
        """Test NodeDiff for changed node"""
        diff = NodeDiff(
            url="https://example.com/page",
            change="changed",
            details={"status_code": {"old": 200, "new": 404}}
        )
        
        assert diff.change == "changed"
        assert "status_code" in diff.details


class TestRunDiff:
    """Tests for RunDiff struct."""

    def test_run_diff_empty(self):
        """Test RunDiff with no changes (identical runs)"""
        diff = RunDiff(
            run_a_id="run1",
            run_b_id="run2",
            nodes_added=[],
            nodes_removed=[],
            edges_added=[],
            edges_removed=[],
            status_changes=[],
            timing_changes=[],
            new_broken_links=[],
            resolved_broken_links=[],
            new_auth_violations=[],
            resolved_auth_violations=[]
        )
        
        assert len(diff.nodes_added) == 0
        assert len(diff.nodes_removed) == 0

    def test_run_diff_with_changes(self):
        """Test RunDiff with multiple types of changes"""
        edge = Edge(
            source="node1",
            target="node2",
            link_text="New link",
            discovered_via=DiscoveryMethod.crawl,
            auth_context=AuthContext.anonymous,
            verified=True
        )
        
        diff = RunDiff(
            run_a_id="run1",
            run_b_id="run2",
            nodes_added=["node3"],
            nodes_removed=["node4"],
            edges_added=[edge],
            edges_removed=[],
            status_changes=[],
            timing_changes=[],
            new_broken_links=[],
            resolved_broken_links=[],
            new_auth_violations=[],
            resolved_auth_violations=[]
        )
        
        assert len(diff.nodes_added) == 1
        assert len(diff.edges_added) == 1


# ============================================================================
# SERIALIZATION TESTS
# ============================================================================

class TestSerialization:
    """Tests for struct serialization/deserialization."""

    def test_serialization_timing_data(self):
        """Test TimingData serialization round-trip"""
        original = TimingData(
            started_at="2024-01-15T10:00:00Z",
            duration_ms=100.5,
            ttfb_ms=50.2
        )
        
        # Convert to dict
        data_dict = original.dict()
        
        # Verify dict structure
        assert isinstance(data_dict, dict)
        assert data_dict["duration_ms"] == 100.5
        
        # Recreate from dict
        reconstructed = TimingData(**data_dict)
        
        assert reconstructed.started_at == original.started_at
        assert reconstructed.duration_ms == original.duration_ms
        assert reconstructed.ttfb_ms == original.ttfb_ms

    def test_serialization_node_capture(self):
        """Test NodeCapture serialization round-trip"""
        resource = Resource(
            url="https://example.com/script.js",
            resource_type=ResourceType.script,
            status_code=200,
            size_bytes=1000,
            timing=None,
            mime_type="application/javascript"
        )
        
        original = NodeCapture(
            auth_context=AuthContext.anonymous,
            http_status=200,
            page_title="Test",
            page_text="Content",
            screenshot_path="/tmp/test.png",
            response_headers=ResponseHeaders(raw={"X-Test": "value"}),
            resources=[resource],
            console_messages=[],
            outgoing_links=["https://example.com/link"],
            cookies=[],
            forms=[],
            security_findings=[]
        )
        
        # Convert to dict
        data_dict = original.dict()
        
        # Verify nested structures
        assert isinstance(data_dict["resources"], list)
        assert len(data_dict["resources"]) == 1
        
        # Recreate from dict
        reconstructed = NodeCapture(**data_dict)
        
        assert reconstructed.page_title == original.page_title
        assert len(reconstructed.resources) == len(original.resources)

    def test_serialization_site_graph(self):
        """Test SiteGraph serialization round-trip"""
        state = NodeState(url="https://example.com")
        node = Node(
            id="node1",
            state=state,
            discovered_via=DiscoveryMethod.manual,
            requires_auth=None,
            auth_contexts_available=[],
            captures=[],
            depth=0
        )
        
        original = SiteGraph(
            nodes={"node1": node},
            edges=[],
            root_url="https://example.com",
            seed_urls=["https://example.com"]
        )
        
        # Convert to dict
        data_dict = original.dict()
        
        # Verify structure
        assert "node1" in data_dict["nodes"]
        assert isinstance(data_dict["edges"], list)
        
        # Recreate from dict
        reconstructed = SiteGraph(**data_dict)
        
        assert reconstructed.root_url == original.root_url
        assert "node1" in reconstructed.nodes

    def test_serialization_run(self):
        """Test Run serialization round-trip"""
        graph = SiteGraph(
            nodes={},
            edges=[],
            root_url="https://example.com",
            seed_urls=[]
        )
        
        original = Run(
            schema_version="1.3",
            run_id="test-123",
            url="https://example.com",
            started_at="2024-01-15T10:00:00Z",
            config_snapshot={"key": "value"},
            phases=[],
            graph=graph
        )
        
        # Convert to dict
        data_dict = original.dict()
        
        # Verify all fields present
        assert data_dict["schema_version"] == "1.3"
        assert data_dict["run_id"] == "test-123"
        
        # Recreate from dict
        reconstructed = Run(**data_dict)
        
        assert reconstructed.schema_version == original.schema_version
        assert reconstructed.run_id == original.run_id


# ============================================================================
# INVARIANT TESTS
# ============================================================================

class TestInvariants:
    """Tests for cross-cutting invariants."""

    def test_schema_version_constant(self):
        """Test SCHEMA_VERSION constant is 1.1"""
        assert SCHEMA_VERSION == "1.3"

    def test_node_state_identity_key_invariant(self):
        """Test NodeState.identity_key() always returns self.url"""
        url = "https://example.com/test/path?query=123"
        state = NodeState(url=url)
        
        # Should always return URL
        assert state.identity_key() == url
        assert state.identity_key() == state.url

    def test_make_run_id_format_invariant(self):
        """Test _make_run_id() format is always YYYYMMDDTHHmmss-<8-hex-chars>"""
        for _ in range(100):
            run_id = _make_run_id()
            
            # Check format
            pattern = r'^\d{8}T\d{6}-[a-f0-9]{8}$'
            assert re.match(pattern, run_id), f"Invalid format: {run_id}"
            
            # Check parts
            parts = run_id.split('-')
            assert len(parts) == 2
            assert len(parts[0]) == 15  # Timestamp
            assert len(parts[1]) == 8   # UUID suffix
