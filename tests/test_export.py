"""Tests for unified export module (SARIF, JSONL, CSV)."""

import csv
import io
import json
import tempfile
from pathlib import Path

from ai_agent_audit.db import FindingsDB
from ai_agent_audit.models import Finding, Severity
from ai_agent_audit.export import export_sarif, export_jsonl, export_csv, export_findings


def _make_db_with_findings():
    """Create an in-memory-like DB with test findings."""
    tmp = tempfile.mkdtemp()
    db_path = Path(tmp) / "test.db"
    db = FindingsDB(db_path=db_path)

    findings = [
        Finding(
            module="test_mod",
            severity=Severity.CRITICAL,
            title="Critical test",
            detail="Critical detail",
            path="/test/path",
            confidence=0.9,
            mitre_attack="T1190",
            owasp_asi="ASI03",
            remediation="Fix it.",
        ),
        Finding(
            module="test_mod2",
            severity=Severity.WARNING,
            title="Warning test",
            detail="Warning detail",
            confidence=0.6,
        ),
        Finding(
            module="test_mod3",
            severity=Severity.INFO,
            title="Info test",
            detail="Info detail",
            confidence=0.3,
        ),
    ]
    for f in findings:
        db.insert(f)
    return db, tmp


class TestExportJSONL:
    def test_jsonl_output_format(self):
        db, _ = _make_db_with_findings()
        text = export_jsonl(db)
        lines = [l for l in text.strip().split("\n") if l]
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "module" in parsed
            assert "severity" in parsed
            assert "title" in parsed
        db.close()

    def test_jsonl_severity_labels(self):
        db, _ = _make_db_with_findings()
        text = export_jsonl(db)
        lines = [json.loads(l) for l in text.strip().split("\n") if l]
        severities = {r["title"]: r["severity"] for r in lines}
        assert severities["Critical test"] == "CRITICAL"
        assert severities["Warning test"] == "WARNING"
        assert severities["Info test"] == "INFO"
        db.close()

    def test_jsonl_includes_mitre_owasp(self):
        db, _ = _make_db_with_findings()
        text = export_jsonl(db)
        lines = [json.loads(l) for l in text.strip().split("\n") if l]
        critical = next(r for r in lines if r["title"] == "Critical test")
        assert critical["mitre_attack"] == "T1190"
        assert critical["owasp_asi"] == "ASI03"
        db.close()


class TestExportCSV:
    def test_csv_output_format(self):
        db, _ = _make_db_with_findings()
        text = export_csv(db)
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 3
        assert "module" in reader.fieldnames
        assert "severity" in reader.fieldnames
        db.close()

    def test_csv_severity_labels(self):
        db, _ = _make_db_with_findings()
        text = export_csv(db)
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        severities = {r["title"]: r["severity"] for r in rows}
        assert severities["Critical test"] == "CRITICAL"
        db.close()


class TestExportSARIF:
    def test_sarif_from_db(self):
        db, _ = _make_db_with_findings()
        text = export_sarif(db)
        sarif = json.loads(text)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 3
        db.close()


class TestExportFindings:
    def test_export_to_file(self):
        db, tmp = _make_db_with_findings()
        out_path = str(Path(tmp) / "out.jsonl")
        content = export_findings(db, fmt="jsonl", output_path=out_path)
        assert Path(out_path).exists()
        file_content = Path(out_path).read_text()
        assert "Critical test" in file_content
        db.close()

    def test_export_unknown_format(self):
        db, _ = _make_db_with_findings()
        try:
            export_findings(db, fmt="xml")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "xml" in str(e)
        db.close()

    def test_export_csv_format(self):
        db, _ = _make_db_with_findings()
        content = export_findings(db, fmt="csv")
        assert "module" in content  # CSV header
        assert "Critical test" in content
        db.close()
