"""Phase 4: Report generation -- JSON and HTML output."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from webprobe.models import PhaseStatus, Run

HTML_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>webprobe report — {{ run.url }}</title>
<style>
  :root { --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff; --red: #f85149;
          --green: #3fb950; --yellow: #d29922; --border: #30363d; --card: #161b22; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--fg); line-height: 1.6; padding: 2rem; max-width: 1400px; margin: 0 auto; }
  h1 { color: var(--accent); margin-bottom: 0.5rem; }
  h2 { color: var(--fg); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin: 2rem 0 1rem; }
  h3 { color: var(--fg); margin: 1rem 0 0.5rem; }
  .meta { color: #8b949e; margin-bottom: 2rem; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; }
  .card .label { color: #8b949e; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .card .value { font-size: 1.8rem; font-weight: 600; }
  .card .value.green { color: var(--green); }
  .card .value.red { color: var(--red); }
  .card .value.yellow { color: var(--yellow); }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); }
  th { color: #8b949e; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
  tr:hover { background: rgba(88,166,255,0.04); }
  .status-ok { color: var(--green); }
  .status-err { color: var(--red); }
  .status-warn { color: var(--yellow); }
  .badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px; font-size: 0.8rem; font-weight: 600; }
  .badge-auth { background: rgba(210,153,34,0.15); color: var(--yellow); }
  .badge-public { background: rgba(63,185,80,0.15); color: var(--green); }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .timing { font-variant-numeric: tabular-nums; }
  .screenshot { max-width: 400px; border: 1px solid var(--border); border-radius: 4px; margin: 0.5rem 0; }
  details { margin: 0.5rem 0; }
  summary { cursor: pointer; color: var(--accent); }
  pre { background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: 0.75rem; overflow-x: auto; font-size: 0.85rem; }
  .console-error { color: var(--red); }
  .console-warning { color: var(--yellow); }
  .sev-critical { color: #ff4040; font-weight: 700; }
  .sev-high { color: var(--red); font-weight: 600; }
  .sev-medium { color: var(--yellow); }
  .sev-low { color: #8b949e; }
  .sev-info { color: #58a6ff; }
  .badge-critical { background: rgba(255,64,64,0.15); color: #ff4040; }
  .badge-high { background: rgba(248,81,73,0.15); color: var(--red); }
  .badge-medium { background: rgba(210,153,34,0.15); color: var(--yellow); }
  .badge-low { background: rgba(139,148,158,0.15); color: #8b949e; }
  .badge-info { background: rgba(88,166,255,0.15); color: #58a6ff; }
</style>
</head>
<body>

<h1>webprobe report</h1>
<div class="meta">
  <strong>{{ run.url }}</strong><br>
  Run ID: {{ run.run_id }}<br>
  Started: {{ run.started_at }}<br>
  {% if run.completed_at %}Completed: {{ run.completed_at }}<br>{% endif %}
  Schema: {{ run.schema_version }}
</div>

{% if analysis %}
<div class="summary">
  <div class="card">
    <div class="label">Pages</div>
    <div class="value">{{ analysis.graph_metrics.total_nodes }}</div>
  </div>
  <div class="card">
    <div class="label">Links</div>
    <div class="value">{{ analysis.graph_metrics.total_edges }}</div>
  </div>
  <div class="card">
    <div class="label">Broken Links</div>
    <div class="value {{ 'red' if analysis.broken_links else 'green' }}">{{ analysis.broken_links|length }}</div>
  </div>
  <div class="card">
    <div class="label">Auth Violations</div>
    <div class="value {{ 'red' if analysis.auth_violations else 'green' }}">{{ analysis.auth_violations|length }}</div>
  </div>
  <div class="card">
    <div class="label">Timing Outliers</div>
    <div class="value {{ 'yellow' if analysis.timing_outliers else 'green' }}">{{ analysis.timing_outliers|length }}</div>
  </div>
  <div class="card">
    <div class="label">Edge Coverage</div>
    <div class="value">{{ "%.0f"|format(analysis.graph_metrics.edge_coverage * 100) }}%</div>
  </div>
  <div class="card">
    <div class="label">Cyclomatic Complexity</div>
    <div class="value">{{ analysis.graph_metrics.cyclomatic_complexity }}</div>
  </div>
  <div class="card">
    <div class="label">Prime Paths</div>
    <div class="value">{{ analysis.prime_paths|length }}</div>
  </div>
  <div class="card">
    <div class="label">Security Findings</div>
    <div class="value {{ 'red' if analysis.security_findings|selectattr('severity', 'equalto', 'critical')|list or analysis.security_findings|selectattr('severity', 'equalto', 'high')|list else 'yellow' if analysis.security_findings else 'green' }}">{{ analysis.security_findings|length }}</div>
  </div>
  {% if source_analysis %}
  <div class="card">
    <div class="label">Source Files</div>
    <div class="value">{{ source_analysis.scanned_files }}</div>
  </div>
  <div class="card">
    <div class="label">Source Findings</div>
    <div class="value {{ 'red' if source_analysis.findings|selectattr('severity', 'equalto', 'critical')|list or source_analysis.findings|selectattr('severity', 'equalto', 'high')|list else 'yellow' if source_analysis.findings else 'green' }}">{{ source_analysis.findings|length }}</div>
  </div>
  {% endif %}
  {% if runtime_canary %}
  <div class="card">
    <div class="label">Canary Inputs</div>
    <div class="value">{{ runtime_canary.discovered_inputs }}</div>
  </div>
  <div class="card">
    <div class="label">Canary Findings</div>
    <div class="value {{ 'red' if runtime_canary.findings|selectattr('severity', 'equalto', 'critical')|list or runtime_canary.findings|selectattr('severity', 'equalto', 'high')|list else 'yellow' if runtime_canary.findings else 'green' }}">{{ runtime_canary.findings|length }}</div>
  </div>
  {% endif %}
</div>
{% endif %}

<h2>Phase Timing</h2>
<table>
  <tr><th>Phase</th><th>Status</th><th>Duration</th></tr>
  {% for p in run.phases %}
  <tr>
    <td>{{ p.phase }}</td>
    <td class="{{ 'status-ok' if p.status == 'completed' else 'status-err' if p.status == 'failed' else '' }}">{{ p.status }}</td>
    <td class="timing">{{ "%.0f"|format(p.duration_ms) if p.duration_ms else '—' }} ms</td>
  </tr>
  {% endfor %}
</table>

<h2>Pages ({{ nodes|length }})</h2>
<table>
  <tr><th>URL</th><th>Auth</th><th>Status</th><th>TTFB</th><th>Load</th><th>Resources</th><th>Console Errors</th></tr>
  {% for node in nodes %}
  <tr>
    <td><a href="#node-{{ loop.index }}">{{ node.id }}</a></td>
    <td>{% if node.requires_auth %}<span class="badge badge-auth">auth</span>{% else %}<span class="badge badge-public">public</span>{% endif %}</td>
    {% if node.captures %}
    {% set cap = node.captures[0] %}
    <td class="{{ 'status-ok' if cap.http_status and cap.http_status < 400 else 'status-err' }}">{{ cap.http_status or '—' }}</td>
    <td class="timing">{{ "%.0f"|format(cap.timing.ttfb_ms) if cap.timing and cap.timing.ttfb_ms else '—' }} ms</td>
    <td class="timing">{{ "%.0f"|format(cap.load_event_ms) if cap.load_event_ms else '—' }} ms</td>
    <td>{{ cap.resources|length }}</td>
    <td class="{{ 'status-err' if cap.console_messages|selectattr('level', 'equalto', 'error')|list else '' }}">
      {{ cap.console_messages|selectattr('level', 'equalto', 'error')|list|length }}
    </td>
    {% else %}
    <td>—</td><td>—</td><td>—</td><td>—</td><td>—</td>
    {% endif %}
  </tr>
  {% endfor %}
</table>

{% if analysis and analysis.broken_links %}
<h2>Broken Links ({{ analysis.broken_links|length }})</h2>
<table>
  <tr><th>Source</th><th>Target</th><th>Status</th><th>Error</th></tr>
  {% for bl in analysis.broken_links %}
  <tr>
    <td>{{ bl.source }}</td>
    <td>{{ bl.target }}</td>
    <td class="status-err">{{ bl.status_code or '—' }}</td>
    <td>{{ bl.error }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

{% if analysis and analysis.auth_violations %}
<h2>Auth Boundary Violations ({{ analysis.auth_violations|length }})</h2>
<table>
  <tr><th>URL</th><th>Evidence</th></tr>
  {% for av in analysis.auth_violations %}
  <tr>
    <td>{{ av.url }}</td>
    <td>{{ av.evidence }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

{% if analysis and analysis.timing_outliers %}
<h2>Timing Outliers ({{ analysis.timing_outliers|length }})</h2>
<table>
  <tr><th>URL</th><th>Metric</th><th>Value</th><th>Mean</th><th>Z-Score</th></tr>
  {% for to in analysis.timing_outliers %}
  <tr>
    <td>{{ to.url }}</td>
    <td>{{ to.metric }}</td>
    <td class="timing status-warn">{{ "%.0f"|format(to.value_ms) }} ms</td>
    <td class="timing">{{ "%.0f"|format(to.mean_ms) }} ms</td>
    <td>{{ "%.1f"|format(to.z_score) }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

{% if analysis and analysis.security_findings %}
<h2>Security Findings ({{ analysis.security_findings|length }})</h2>
{% set sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4} %}
<table>
  <tr><th>Severity</th><th>Category</th><th>Finding</th><th>Location</th><th>Detail</th></tr>
  {% for sf in analysis.security_findings|sort(attribute='severity') %}
  <tr>
    <td><span class="badge badge-{{ sf.severity }}">{{ sf.severity }}</span></td>
    <td>{{ sf.category }}</td>
    <td>{{ sf.title }}</td>
    <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
      {% if sf.source_path %}{{ sf.source_path }}{% if sf.source_line %}:{{ sf.source_line }}{% endif %}{% else %}{{ sf.url }}{% endif %}
    </td>
    <td>{{ sf.detail }}{% if sf.evidence %}<br><code style="font-size:0.8rem;color:#8b949e;">{{ sf.evidence[:120] }}</code>{% endif %}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

{% if source_analysis %}
<h2>Source Analysis</h2>
<div class="summary">
  <div class="card">
    <div class="label">Root</div>
    <div class="value" style="font-size:1rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ source_analysis.root_path }}</div>
  </div>
  <div class="card">
    <div class="label">Scanned Files</div>
    <div class="value">{{ source_analysis.scanned_files }}</div>
  </div>
  <div class="card">
    <div class="label">Lines</div>
    <div class="value">{{ source_analysis.total_lines }}</div>
  </div>
  <div class="card">
    <div class="label">Skipped Files</div>
    <div class="value">{{ source_analysis.skipped_files }}</div>
  </div>
</div>
{% endif %}

{% if runtime_canary %}
<h2>Runtime Canary Probing</h2>
<div class="summary">
  <div class="card">
    <div class="label">Target</div>
    <div class="value" style="font-size:1rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ runtime_canary.target_url }}</div>
  </div>
  <div class="card">
    <div class="label">Inputs</div>
    <div class="value">{{ runtime_canary.discovered_inputs }}</div>
  </div>
  <div class="card">
    <div class="label">Requests</div>
    <div class="value">{{ runtime_canary.requests_sent }}</div>
  </div>
  <div class="card">
    <div class="label">Skipped</div>
    <div class="value">{{ runtime_canary.skipped_inputs }}</div>
  </div>
</div>
{% if runtime_canary.observations %}
<table>
  <tr><th>Input</th><th>Status</th><th>Reflected</th><th>Contexts</th><th>URL</th></tr>
  {% for obs in runtime_canary.observations %}
  <tr>
    <td>{{ obs.input_name }}</td>
    <td>{{ obs.status_code or obs.error or '—' }}</td>
    <td>{{ 'yes' if obs.reflected else 'no' }}</td>
    <td>{{ ', '.join(obs.reflection_contexts) }}</td>
    <td style="max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ obs.url }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}
{% endif %}

{% if analysis and analysis.compliance %}
<h2>Compliance Summary</h2>
<div class="summary">
  {% for std_key, count in analysis.compliance.violations_by_standard.items() %}
  <div class="card">
    <div class="label">{{ std_key }}</div>
    <div class="value {{ 'red' if count else 'green' }}">{{ count }}</div>
  </div>
  {% endfor %}
</div>

{% set flagged_controls = [] %}
{% for ctrl in analysis.compliance.controls %}
{% if ctrl.finding_count > 0 %}
{% set _ = flagged_controls.append(ctrl) %}
{% endif %}
{% endfor %}
{% if flagged_controls %}
<h3>Controls with Findings</h3>
<table>
  <tr><th>Standard</th><th>Control</th><th>Name</th><th>Testable</th><th>Findings</th><th>Max Severity</th></tr>
  {% for ctrl in analysis.compliance.controls|sort(attribute='finding_count', reverse=True) %}
  {% if ctrl.finding_count > 0 %}
  <tr>
    <td>{{ ctrl.standard_name }}</td>
    <td>{{ ctrl.control_id }}</td>
    <td>{{ ctrl.control_name }}</td>
    <td>{{ ctrl.testable }}</td>
    <td>{{ ctrl.finding_count }}</td>
    <td>{% if ctrl.max_severity %}<span class="badge badge-{{ ctrl.max_severity }}">{{ ctrl.max_severity }}</span>{% endif %}</td>
  </tr>
  {% endif %}
  {% endfor %}
</table>
{% endif %}

{% if analysis.compliance.untestable_controls %}
<h3>Controls Requiring Manual Review</h3>
<table>
  <tr><th>Standard</th><th>Control</th><th>Name</th><th>Notes</th></tr>
  {% for ctrl in analysis.compliance.untestable_controls %}
  {% if ctrl.manual_notes %}
  <tr>
    <td>{{ ctrl.standard_name }}</td>
    <td>{{ ctrl.control_id }}</td>
    <td>{{ ctrl.control_name }}</td>
    <td>{{ ctrl.manual_notes }}</td>
  </tr>
  {% endif %}
  {% endfor %}
</table>
{% endif %}
{% endif %}

{% set advocate_findings = [] %}
{% if analysis and analysis.security_findings %}
{% for sf in analysis.security_findings %}{% if sf.category is defined and sf.category == 'advocate' %}{% set _ = advocate_findings.append(sf) %}{% endif %}{% endfor %}
{% endif %}
{% if advocate_findings %}
<h2>Advocate Review ({{ advocate_findings|length }} findings)</h2>
<table>
  <tr><th>Severity</th><th>Finding</th><th>Detail</th><th>URL</th></tr>
  {% for sf in advocate_findings %}
  <tr>
    <td><span class="badge badge-{{ sf.severity }}">{{ sf.severity }}</span></td>
    <td>{{ sf.title }}</td>
    <td>{{ sf.detail }}{% if sf.evidence %}<br><code style="font-size:0.8rem;color:#8b949e;">{{ sf.evidence[:200] }}</code>{% endif %}</td>
    <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ sf.url }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

<h2>Node Details</h2>
{% for node in nodes %}
<div class="card" id="node-{{ loop.index }}" style="margin-bottom: 1rem;">
  <h3>{{ node.id }}</h3>
  <p>
    Depth: {{ node.depth }} |
    Discovered via: {{ node.discovered_via }} |
    Auth: {% if node.requires_auth %}<span class="badge badge-auth">required</span>{% else %}<span class="badge badge-public">public</span>{% endif %}
  </p>
  {% for capture in node.captures %}
  <details{% if loop.first %} open{% endif %}>
    <summary>{{ capture.auth_context }} — HTTP {{ capture.http_status or 'N/A' }}
      {% if capture.timing %}({{ "%.0f"|format(capture.timing.duration_ms) }} ms){% endif %}
    </summary>
    <p><strong>{{ capture.page_title }}</strong></p>
    {% if capture.timing and capture.timing.ttfb_ms %}
    <p class="timing">TTFB: {{ "%.0f"|format(capture.timing.ttfb_ms) }} ms |
      DCL: {{ "%.0f"|format(capture.dom_content_loaded_ms) if capture.dom_content_loaded_ms else '—' }} ms |
      Load: {{ "%.0f"|format(capture.load_event_ms) if capture.load_event_ms else '—' }} ms
    </p>
    {% endif %}
    {% if capture.resources %}
    <details>
      <summary>Resources ({{ capture.resources|length }})</summary>
      <table>
        <tr><th>Type</th><th>URL</th><th>Status</th><th>Size</th><th>MIME</th></tr>
        {% for res in capture.resources %}
        <tr>
          <td>{{ res.resource_type }}</td>
          <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ res.url }}</td>
          <td class="{{ 'status-ok' if res.status_code and res.status_code < 400 else 'status-err' }}">{{ res.status_code or '—' }}</td>
          <td class="timing">{{ res.size_bytes if res.size_bytes is not none else '—' }}</td>
          <td>{{ res.mime_type }}</td>
        </tr>
        {% endfor %}
      </table>
    </details>
    {% endif %}
    {% set errors = capture.console_messages|selectattr('level', 'equalto', 'error')|list %}
    {% set warnings = capture.console_messages|selectattr('level', 'equalto', 'warning')|list %}
    {% if errors or warnings %}
    <details>
      <summary>Console ({{ errors|length }} errors, {{ warnings|length }} warnings)</summary>
      {% for msg in capture.console_messages %}
      <div class="{{ 'console-error' if msg.level == 'error' else 'console-warning' if msg.level == 'warning' else '' }}">
        [{{ msg.level }}] {{ msg.text }}
      </div>
      {% endfor %}
    </details>
    {% endif %}
    {% if capture.outgoing_links %}
    <details>
      <summary>Links ({{ capture.outgoing_links|length }})</summary>
      <ul>
        {% for link in capture.outgoing_links %}
        <li><a href="{{ link }}">{{ link }}</a></li>
        {% endfor %}
      </ul>
    </details>
    {% endif %}
    {% if capture.security_findings %}
    <details>
      <summary>Security ({{ capture.security_findings|length }} findings)</summary>
      <table>
        <tr><th>Severity</th><th>Finding</th><th>Detail</th></tr>
        {% for sf in capture.security_findings %}
        <tr>
          <td><span class="badge badge-{{ sf.severity }}">{{ sf.severity }}</span></td>
          <td>{{ sf.title }}</td>
          <td>{{ sf.detail }}{% if sf.evidence %}<br><code style="font-size:0.8rem;color:#8b949e;">{{ sf.evidence[:120] }}</code>{% endif %}</td>
        </tr>
        {% endfor %}
      </table>
    </details>
    {% endif %}
    {% if capture.screenshot_path %}
    <details>
      <summary>Screenshot</summary>
      <img class="screenshot" src="{{ capture.screenshot_path }}" alt="Screenshot of {{ node.id }}">
    </details>
    {% endif %}
  </details>
  {% endfor %}
</div>
{% endfor %}

{% if run.advocate_cost %}
<h2>Advocate Cost</h2>
<div class="summary">
  <div class="card">
    <div class="label">LLM Calls</div>
    <div class="value">{{ run.advocate_cost.total_calls }}</div>
  </div>
  <div class="card">
    <div class="label">Input Tokens</div>
    <div class="value">{{ run.advocate_cost.total_input_tokens }}</div>
  </div>
  <div class="card">
    <div class="label">Output Tokens</div>
    <div class="value">{{ run.advocate_cost.total_output_tokens }}</div>
  </div>
  <div class="card">
    <div class="label">Estimated Cost</div>
    <div class="value">${{ "%.4f"|format(run.advocate_cost.total_cost_usd) }}</div>
  </div>
</div>
{% endif %}

{% if run.explore_cost %}
<h2>Exploration Cost</h2>
<div class="summary">
  <div class="card">
    <div class="label">LLM Calls</div>
    <div class="value">{{ run.explore_cost.total_calls }}</div>
  </div>
  <div class="card">
    <div class="label">Input Tokens</div>
    <div class="value">{{ run.explore_cost.total_input_tokens }}</div>
  </div>
  <div class="card">
    <div class="label">Output Tokens</div>
    <div class="value">{{ run.explore_cost.total_output_tokens }}</div>
  </div>
  <div class="card">
    <div class="label">Estimated Cost</div>
    <div class="value">${{ "%.4f"|format(run.explore_cost.total_cost_usd) }}</div>
  </div>
</div>
{% endif %}

<footer style="margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: #8b949e; font-size: 0.85rem;">
  Generated by <strong>webprobe</strong> v{{ version }} | Schema {{ run.schema_version }}
</footer>

</body>
</html>
""")


def _source_analysis_for_template(run: Run):
    """Return source analysis only when it has the real iterable shape."""
    source_analysis = getattr(run, "source_analysis", None)
    findings = getattr(source_analysis, "findings", None)
    if isinstance(findings, list):
        return source_analysis
    return None


def _runtime_canary_for_template(run: Run):
    """Return runtime canary data only when it has the real iterable shape."""
    runtime_canary = getattr(run, "runtime_canary", None)
    observations = getattr(runtime_canary, "observations", None)
    findings = getattr(runtime_canary, "findings", None)
    if isinstance(observations, list) and isinstance(findings, list):
        return runtime_canary
    return None


def generate_report(
    run: Run,
    run_dir: Path,
    formats: list[str] | None = None,
) -> PhaseStatus:
    """Phase 4: Generate JSON and/or HTML reports."""
    phase = PhaseStatus(
        phase="report",
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    start = time.monotonic()

    if formats is None:
        formats = ["json", "html"]

    if "json" in formats:
        report_path = run_dir / "report.json"
        report_path.write_text(run.model_dump_json(indent=2))

    if "html" in formats:
        from webprobe import __version__
        nodes = sorted(run.graph.nodes.values(), key=lambda n: n.id)
        html = HTML_TEMPLATE.render(
            run=run,
            analysis=run.analysis,
            nodes=nodes,
            source_analysis=_source_analysis_for_template(run),
            runtime_canary=_runtime_canary_for_template(run),
            version=__version__,
        )
        html_path = run_dir / "report.html"
        html_path.write_text(html)

    duration = (time.monotonic() - start) * 1000
    phase.status = "completed"
    phase.completed_at = datetime.now(timezone.utc).isoformat()
    phase.duration_ms = duration

    return phase
