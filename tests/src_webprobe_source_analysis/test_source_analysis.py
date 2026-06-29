from __future__ import annotations

from pathlib import Path

from webprobe.config import normalize_compliance_standards
from webprobe.models import SecurityCategory, SecuritySeverity
from webprobe.source_analysis import scan_repository


def test_source_scan_detects_secrets_and_request_to_sink(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        "\n".join([
            "from flask import request, redirect",
            "AWS_KEY = 'AKIA1234567890ABCDEF'",
            "SECRET_KEY = 'supersecretpassword'",
            "def handler(cursor):",
            "    user_id = request.args['user_id']",
            "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            "    return redirect(request.args.get('next'))",
        ])
    )

    result, phase = scan_repository(tmp_path)

    assert phase.status == "completed"
    assert result.scanned_files == 1
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "source.secrets.aws_access_key" in rule_ids
    assert "source.secrets.generic_assignment" in rule_ids
    assert "source.injection.sql_interpolation" in rule_ids
    assert "source.taint.source_to_sink_window" in rule_ids
    assert "source.injection.open_redirect_surface" in rule_ids
    assert all(f.source_path == "app.py" for f in result.findings)
    assert all("AKIA1234567890ABCDEF" not in f.evidence for f in result.findings)


def test_source_scan_downgrades_test_fixture_crypto(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    fixture = tests_dir / "test_hashes.py"
    fixture.write_text("digest = hashlib.md5(b'fixture').hexdigest()\n")

    result, _ = scan_repository(tmp_path)

    [finding] = result.findings
    assert finding.category == SecurityCategory.cryptography
    assert finding.severity == SecuritySeverity.info
    assert finding.source_context["path_context"] == "test_or_fixture"


def test_compliance_aliases_accept_requested_spellings() -> None:
    assert normalize_compliance_standards("SOC2, ISO, CJIS, HIPPA") == [
        "soc2",
        "iso_27001_2022",
        "cjis",
        "hipaa",
    ]
